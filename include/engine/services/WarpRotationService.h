#pragma once

#include <QElapsedTimer>
#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>

class QTimer;

namespace Engine {
    class ConnectionManager;

    // Keeps the built-in WARP outbound off exit IPs the user blacklisted.
    // The blacklist holds public exit IPs; every endpoint's exit IP is cached the first time it is seen, so a rotation can
    // pick a scanned endpoint whose exit IP is known good before it dials anything.
    // Main thread only; exit lookups run on worker threads. Lives for the process, like the other services.
    class WarpRotationService final : public QObject {
        Q_OBJECT

    public:
        struct BlacklistEntry {
            QString ip;
            bool enabled = true;
        };

        static WarpRotationService *instance();

        [[nodiscard]] QList<BlacklistEntry> blacklist() const;

        // "" on success, else a reason fit for a dialog.
        QString addToBlacklist(const QString &ip);
        void setBlacklisted(const QString &ip, bool listed);
        void removeFromBlacklist(const QString &ip);
        [[nodiscard]] bool isBlacklisted(const QString &ip) const;

        [[nodiscard]] bool rotating() const { return m_rotating; }
        // Canonical "host:port" of the WARP outbound in the active mode; empty when WARP has no endpoint yet.
        [[nodiscard]] QString currentEndpoint() const;
        [[nodiscard]] QString learnedExit(const QString &endpoint) const;

        // Before a start's config is built: dial a good endpoint when the current one's exit IP is blacklisted.
        // Returns what it did, for the log; "" when there was nothing to do.
        QString autoSkipBeforeStart();

        // Once the chain is up: cache the exit IP this endpoint produced. Emissions feed a running rotation.
        void noteConnected();

        // Blacklists the current exit IP, then walks scanned endpoints until one yields a usable exit IP.
        void rotate();
        void cancel();

    signals:
        void blacklistChanged();
        void stateChanged();
        void finished(bool ok, const QString &message);
        // Empty ip: the lookup failed or the endpoint did not come up.
        void exitChecked(const QString &endpoint, const QString &ip);

    private:
        explicit WarpRotationService();

        struct Candidate {
            QString endpoint;
            int latencyMs = 0;
            QString exitIp;
        };

        // Latest completed WARP scan for the active mode, ranked: known-good exits by latency, then unobserved ones.
        [[nodiscard]] QList<Candidate> candidates() const;
        [[nodiscard]] QString takeNextCandidate();

        // "" on success.
        QString applyEndpoint(const QString &endpoint);

        void lookupCurrentExit(const QString &endpoint);
        void blockCurrentExit(const QString &endpoint, const QString &exitIp);
        void startNextAttempt();
        void finish(bool ok, const QString &message);
        void attachConnection();
        [[nodiscard]] ConnectionManager *connection() const;

        void onStartFinished(int outcome, const QString &error);
        void onExitChecked(const QString &endpoint, const QString &ip);

        bool m_rotating = false;
        bool m_readingCurrent = false;
        int m_attempt = 0;
        QElapsedTimer m_clock;
        QStringList m_tried;
        QList<Candidate> m_pendingCandidates;
        QString m_pendingEndpoint;
        QTimer *m_attemptTimer = nullptr;
        ConnectionManager *m_attached = nullptr;
        QString m_lastMessage;
    };
}
