#include "include/engine/services/WarpRotationService.h"

#include "include/configs/Warp.h"
#include "include/database/DatabaseManager.h"
#include "include/database/IpListsRepo.h"
#include "include/database/IpScansRepo.h"
#include "include/database/WarpExitRepo.h"
#include "include/database/entities/IpScan.h"
#include "include/engine/EditLocks.h"
#include "include/engine/EngineHost.h"
#include "include/engine/EngineTypes.h"
#include "include/engine/ThreadCheck.h"
#include "include/engine/connection/ConnectionManager.h"
#include "include/engine/services/SettingsService.h"
#include "include/global/ExitLookup.hpp"
#include "include/global/Utils.hpp"

#include <QAbstractSocket>
#include <QHostAddress>
#include <QSet>
#include <QTimer>

#include <algorithm>
#include <limits>

namespace Engine {
    namespace {
        constexpr int kWarpRotationMaxAttempts = 8;
        constexpr qint64 kWarpRotationBudgetMs = 180000;
        // One restart plus its exit lookup; a dead endpoint never answers.
        constexpr int kWarpRotationAttemptTimeoutMs = 30000;

        int warpRotationDefaultPort(const QString &mode) {
            return mode == QLatin1String("masque") ? 443 : 2408;
        }

        // The scan names AmneziaWG by the outbound's name; settings drop the "wg".
        QString warpRotationScanMode(const QString &mode) {
            return mode == QLatin1String("amnezia") ? QStringLiteral("amneziawg") : mode;
        }

        QString warpRotationCanonicalIp(const QString &ip) {
            QHostAddress address;
            if (!address.setAddress(ip.trimmed())) return {};
            const auto protocol = address.protocol();
            if (protocol != QAbstractSocket::IPv4Protocol && protocol != QAbstractSocket::IPv6Protocol) return {};
            return address.toString();
        }

        QString warpRotationEndpointText(const QString &host, int port) {
            const QString address = host.contains(QLatin1Char(':')) ? QStringLiteral("[%1]").arg(host) : host;
            return address + QLatin1Char(':') + QString::number(port);
        }

        bool warpRotationLatencyLess(const int left, const int right) {
            // A zero latency is "not measured", so it sorts after every measured one.
            const auto rank = [](int latency) { return latency > 0 ? latency : std::numeric_limits<int>::max(); };
            return rank(left) < rank(right);
        }
    } // namespace

    WarpRotationService *WarpRotationService::instance() {
        static auto *service = new WarpRotationService();
        return service;
    }

    WarpRotationService::WarpRotationService() {
        m_attemptTimer = new QTimer(this);
        m_attemptTimer->setSingleShot(true);
        connect(m_attemptTimer, &QTimer::timeout, this, [this] {
            if (!m_rotating || m_pendingEndpoint.isEmpty()) return;
            MW_show_log(QStringLiteral("[WARP] %1 did not come up; trying another endpoint").arg(m_pendingEndpoint));
            m_pendingEndpoint.clear();
            startNextAttempt();
        });
        connect(this, &WarpRotationService::exitChecked, this, &WarpRotationService::onExitChecked);
    }

    ConnectionManager *WarpRotationService::connection() const {
        auto *host = Engine::host();
        return host == nullptr ? nullptr : host->connection();
    }

    void WarpRotationService::attachConnection() {
        auto *conn = connection();
        if (conn == m_attached) return;
        if (m_attached != nullptr) disconnect(m_attached, nullptr, this, nullptr);
        m_attached = conn;
        if (conn == nullptr) return;
        connect(conn, &ConnectionManager::startFinished, this,
                [this](quint64, int, StartOutcome outcome, const QString &error) {
                    onStartFinished(static_cast<int>(outcome), error);
                });
    }

    QList<WarpRotationService::BlacklistEntry> WarpRotationService::blacklist() const {
        QList<BlacklistEntry> out;
        for (const auto &entry : Configs::dataManager->warpExitRepo->Blacklist()) out.append({entry.ip, entry.enabled});
        return out;
    }

    QString WarpRotationService::addToBlacklist(const QString &ip) {
        ENGINE_CHECK_MAIN_THREAD();
        const auto canonical = warpRotationCanonicalIp(ip);
        if (canonical.isEmpty()) return tr("Enter a valid IPv4 or IPv6 address");
        if (!Configs::dataManager->warpExitRepo->AddToBlacklist(canonical)) {
            return tr("That IP is already listed; enable it in the list instead");
        }
        emit blacklistChanged();
        return {};
    }

    void WarpRotationService::setBlacklisted(const QString &ip, bool listed) {
        ENGINE_CHECK_MAIN_THREAD();
        const auto canonical = warpRotationCanonicalIp(ip);
        if (canonical.isEmpty()) return;
        Configs::dataManager->warpExitRepo->SetEnabled(canonical, listed);
        emit blacklistChanged();
    }

    void WarpRotationService::removeFromBlacklist(const QString &ip) {
        ENGINE_CHECK_MAIN_THREAD();
        const auto canonical = warpRotationCanonicalIp(ip);
        if (canonical.isEmpty()) return;
        Configs::dataManager->warpExitRepo->RemoveFromBlacklist(canonical);
        emit blacklistChanged();
    }

    bool WarpRotationService::isBlacklisted(const QString &ip) const {
        const auto canonical = warpRotationCanonicalIp(ip);
        return !canonical.isEmpty() && Configs::dataManager->warpExitRepo->IsBlocked(canonical);
    }

    QString WarpRotationService::currentEndpoint() const {
        const auto &settings = Configs::dataManager->settingsRepo;
        const bool masque = settings->warp_mode == QLatin1String("masque");
        const QString raw = masque ? settings->warp_masque_ep : settings->warp_ep;
        if (raw.trimmed().isEmpty()) return {};
        QString host;
        int port = 0;
        Configs::SplitWarpEndpoint(raw, warpRotationDefaultPort(settings->warp_mode), host, port);
        if (host.isEmpty() || port <= 0) return {};
        QHostAddress address;
        if (address.setAddress(host)) host = address.toString();
        return warpRotationEndpointText(host, port);
    }

    QString WarpRotationService::learnedExit(const QString &endpoint) const {
        return Configs::dataManager->warpExitRepo->LearnedExit(endpoint);
    }

    QList<WarpRotationService::Candidate> WarpRotationService::candidates() const {
        const auto &settings = Configs::dataManager->settingsRepo;
        const QString wantedMode = warpRotationScanMode(settings->warp_mode);
        std::shared_ptr<Configs::IpScan> latest;
        for (const auto &scan : Configs::dataManager->ipScansRepo->GetAllIpScans()) {
            if (scan == nullptr || scan->kind != Configs::IpScan::Kind::Warp) continue;
            if (scan->config.warp.mode != wantedMode) continue;
            if (scan->result_list_id < 0) continue;
            if (scan->status != Configs::IpScan::Status::Completed && scan->status != Configs::IpScan::Status::Paused) continue;
            if (latest == nullptr || scan->id > latest->id) latest = scan;
        }
        if (latest == nullptr) return {};

        const QString current = currentEndpoint();
        QString host;
        int fallbackPort = 0;
        Configs::SplitWarpEndpoint(current, warpRotationDefaultPort(settings->warp_mode), host, fallbackPort);
        if (fallbackPort <= 0) fallbackPort = warpRotationDefaultPort(settings->warp_mode);

        QList<Candidate> known;
        QList<Candidate> unobserved;
        QSet<QString> seen;
        for (const auto &entry : Configs::dataManager->ipListsRepo->GetEntries(latest->result_list_id)) {
            QHostAddress address;
            if (!address.setAddress(entry.cidr)) continue;
            const int port = entry.port > 0 ? entry.port : fallbackPort;
            if (port <= 0) continue;
            const QString endpoint = warpRotationEndpointText(address.toString(), port);
            if (endpoint == current || seen.contains(endpoint)) continue;
            seen.insert(endpoint);
            const QString exitIp = Configs::dataManager->warpExitRepo->LearnedExit(endpoint);
            if (!exitIp.isEmpty() && Configs::dataManager->warpExitRepo->IsBlocked(exitIp)) continue;
            (exitIp.isEmpty() ? unobserved : known).append({endpoint, entry.latencyMs, exitIp});
        }
        const auto order = [](const Candidate &left, const Candidate &right) {
            if (warpRotationLatencyLess(left.latencyMs, right.latencyMs)) return true;
            if (warpRotationLatencyLess(right.latencyMs, left.latencyMs)) return false;
            return left.endpoint < right.endpoint;
        };
        std::sort(known.begin(), known.end(), order);
        std::sort(unobserved.begin(), unobserved.end(), order);
        return known + unobserved;
    }

    QString WarpRotationService::takeNextCandidate() {
        while (!m_pendingCandidates.isEmpty()) {
            const auto candidate = m_pendingCandidates.takeFirst();
            if (m_tried.contains(candidate.endpoint)) continue;
            return candidate.endpoint;
        }
        return {};
    }

    QString WarpRotationService::applyEndpoint(const QString &endpoint) {
        const bool masque = Configs::dataManager->settingsRepo->warp_mode == QLatin1String("masque");
        Engine::SettingsService::ApplyResult result;
        const auto refused = Engine::SettingsService::Update([endpoint, masque](Configs::SettingsValues &values) {
            if (masque) values.warp_masque_ep = endpoint;
            else values.warp_ep = endpoint;
        }, {.interactive = true}, &result);
        if (refused) return refused->message;
        return {};
    }

    QString WarpRotationService::autoSkipBeforeStart() {
        ENGINE_CHECK_MAIN_THREAD();
        // A rotation drives its own restarts; and an open Routing Settings window writes every warp_* field back on OK.
        if (m_rotating || IsBeingEdited(EditTarget::Routes)) return {};

        const auto &settings = Configs::dataManager->settingsRepo;
        if (!settings->enable_warp || settings->enable_tor || !Configs::WarpConfigured(settings->warp_mode)) return {};

        const QString current = currentEndpoint();
        if (current.isEmpty()) return {};
        const QString exitIp = Configs::dataManager->warpExitRepo->LearnedExit(current);
        if (exitIp.isEmpty() || !Configs::dataManager->warpExitRepo->IsBlocked(exitIp)) return {};

        QStringList tried;
        for (const auto &candidate : candidates()) {
            if (tried.contains(candidate.endpoint)) continue;
            tried.append(candidate.endpoint);
            if (const auto error = applyEndpoint(candidate.endpoint); !error.isEmpty()) continue;
            return QStringLiteral("[WARP] Exit IP %1 is blacklisted; dialing %2 instead").arg(exitIp, candidate.endpoint);
        }
        return QStringLiteral("[WARP] Exit IP %1 is blacklisted and no scanned WARP endpoint is left to try").arg(exitIp);
    }

    void WarpRotationService::noteConnected() {
        ENGINE_CHECK_MAIN_THREAD();
        const auto &settings = Configs::dataManager->settingsRepo;
        if (!settings->enable_warp || settings->enable_tor) return;
        const QString endpoint = currentEndpoint();
        if (endpoint.isEmpty()) return;
        const QString provider = settings->exit_lookup_provider;
        runOnNewThread([this, endpoint, provider] {
            QString error;
            const auto info = Configs_network::LookupExit(provider, &error);
            const QString ip = info.ip.trimmed();
            runOnUiThread([this, endpoint, ip] {
                if (!ip.isEmpty()) {
                    Configs::dataManager->warpExitRepo->LearnExit(endpoint, ip);
                    if (Configs::dataManager->warpExitRepo->IsBlocked(ip)) {
                        MW_show_log(QStringLiteral("[WARP] Exit IP %1 is in the blacklist; press Rotate IP").arg(ip));
                    }
                }
                emit exitChecked(endpoint, ip);
            });
        });
    }

    void WarpRotationService::rotate() {
        ENGINE_CHECK_MAIN_THREAD();
        if (m_rotating) return;

        const auto &settings = Configs::dataManager->settingsRepo;
        if (!settings->enable_warp || settings->enable_tor) {
            emit finished(false, tr("WARP is not the active exit"));
            return;
        }
        if (!Configs::WarpConfigured(settings->warp_mode)) {
            emit finished(false, tr("WARP has no device for this mode yet; register one in Routing Settings"));
            return;
        }
        if (IsBeingEdited(EditTarget::Routes)) {
            emit finished(false, tr("Routing Settings is open; close it and try again"));
            return;
        }
        auto *conn = connection();
        if (conn == nullptr || conn->connectionState() != ConnectionState::Running) {
            emit finished(false, tr("Start a profile with WARP as the exit first"));
            return;
        }
        const QString startEndpoint = currentEndpoint();
        if (startEndpoint.isEmpty()) {
            emit finished(false, tr("WARP has no endpoint in Routing Settings yet, so there is no exit IP to blacklist"));
            return;
        }
        // Nothing to fall back to: refuse before blacklisting, or the working endpoint would be lost for nothing.
        const auto list = candidates();
        if (list.isEmpty()) {
            emit finished(false, tr("No other scanned WARP endpoint is available; run a WARP scan for %1 first")
                                     .arg(settings->warp_mode));
            return;
        }

        attachConnection();
        m_rotating = true;
        m_readingCurrent = true;
        m_attempt = 0;
        m_tried.clear();
        m_pendingCandidates = list;
        m_lastMessage.clear();
        m_clock.start();
        emit stateChanged();

        const QString cached = Configs::dataManager->warpExitRepo->LearnedExit(startEndpoint);
        if (!cached.isEmpty()) {
            m_readingCurrent = false;
            blockCurrentExit(startEndpoint, cached);
            return;
        }
        lookupCurrentExit(startEndpoint);
    }

    void WarpRotationService::lookupCurrentExit(const QString &endpoint) {
        const QString provider = Configs::dataManager->settingsRepo->exit_lookup_provider;
        runOnNewThread([this, endpoint, provider] {
            QString error;
            const auto info = Configs_network::LookupExit(provider, &error);
            const QString ip = info.ip.trimmed();
            runOnUiThread([this, endpoint, ip] {
                if (!m_rotating || !m_readingCurrent) return;
                m_readingCurrent = false;
                if (ip.isEmpty()) {
                    finish(false, tr("Could not read the current WARP exit IP, so nothing was blacklisted"));
                    return;
                }
                Configs::dataManager->warpExitRepo->LearnExit(endpoint, ip);
                blockCurrentExit(endpoint, ip);
            });
        });
    }

    void WarpRotationService::blockCurrentExit(const QString &endpoint, const QString &exitIp) {
        if (Configs::dataManager->warpExitRepo->IsBlocked(exitIp)) {
            MW_show_log(QStringLiteral("[WARP] Exit IP %1 is already blacklisted").arg(exitIp));
        } else {
            Configs::dataManager->warpExitRepo->AddToBlacklist(exitIp);
            emit blacklistChanged();
            MW_show_log(QStringLiteral("[WARP] Blacklisted exit IP %1 (endpoint %2)").arg(exitIp, endpoint));
        }
        startNextAttempt();
    }

    void WarpRotationService::startNextAttempt() {
        if (!m_rotating) return;
        if (m_attempt >= kWarpRotationMaxAttempts || m_clock.elapsed() >= kWarpRotationBudgetMs) {
            finish(false, m_lastMessage.isEmpty()
                              ? tr("Gave up after %1 endpoints; every exit IP was blacklisted or unreachable").arg(m_attempt)
                              : m_lastMessage);
            return;
        }
        auto *conn = connection();
        if (conn == nullptr) {
            finish(false, tr("No engine connection is available; rotation cancelled"));
            return;
        }
        // A manual stop clears the resume target, so nothing would restart and there is nothing left to rotate.
        if (conn->connectionState() == ConnectionState::Idle && !conn->restartPending()) {
            finish(false, tr("The connection was stopped; rotation cancelled"));
            return;
        }
        const QString endpoint = takeNextCandidate();
        if (endpoint.isEmpty()) {
            finish(false, tr("No scanned WARP endpoint is left to try; run a WARP scan in the scanner first"));
            return;
        }
        if (const auto error = applyEndpoint(endpoint); !error.isEmpty()) {
            finish(false, error);
            return;
        }
        ++m_attempt;
        m_tried.append(endpoint);
        m_pendingEndpoint = endpoint;
        m_attemptTimer->start(kWarpRotationAttemptTimeoutMs);
        m_lastMessage = tr("Tried %1 endpoints; every exit IP was blacklisted or unreachable").arg(m_attempt);
        MW_show_log(QStringLiteral("[WARP] Trying %1 (attempt %2)").arg(endpoint).arg(m_attempt));
        emit stateChanged();
        conn->applyPendingRestart();
        // A stop that landed while the request was queued: nothing restarted, and nothing will.
        if (conn->connectionState() == ConnectionState::Idle && !conn->restartPending()) {
            finish(false, tr("The connection was stopped; rotation cancelled"));
        }
    }

    void WarpRotationService::onStartFinished(int outcome, const QString &error) {
        if (!m_rotating || m_pendingEndpoint.isEmpty()) return;
        if (static_cast<StartOutcome>(outcome) == StartOutcome::Started) return;
        m_lastMessage = tr("The chain did not come up on %1").arg(m_pendingEndpoint);
        MW_show_log(QStringLiteral("[WARP] %1 did not start: %2").arg(m_pendingEndpoint, error));
        m_attemptTimer->stop();
        m_pendingEndpoint.clear();
        startNextAttempt();
    }

    void WarpRotationService::onExitChecked(const QString &endpoint, const QString &ip) {
        if (!m_rotating || m_pendingEndpoint.isEmpty() || endpoint != m_pendingEndpoint) return;
        m_attemptTimer->stop();
        m_pendingEndpoint.clear();
        if (ip.isEmpty()) {
            m_lastMessage = tr("No exit IP came back through %1").arg(endpoint);
            startNextAttempt();
            return;
        }
        if (Configs::dataManager->warpExitRepo->IsBlocked(ip)) {
            m_lastMessage = tr("Every exit IP tried is blacklisted");
            MW_show_log(QStringLiteral("[WARP] %1 exits through blacklisted IP %2").arg(endpoint, ip));
            startNextAttempt();
            return;
        }
        finish(true, tr("Rotated to %1; the exit IP is %2").arg(endpoint, ip));
    }

    void WarpRotationService::finish(bool ok, const QString &message) {
        m_attemptTimer->stop();
        m_rotating = false;
        m_readingCurrent = false;
        m_pendingEndpoint.clear();
        m_pendingCandidates.clear();
        m_tried.clear();
        emit stateChanged();
        emit finished(ok, message);
    }

    void WarpRotationService::cancel() {
        ENGINE_CHECK_MAIN_THREAD();
        if (!m_rotating) return;
        finish(false, tr("Rotation cancelled"));
    }
} // namespace Engine
