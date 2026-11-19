#include "include/database/WarpExitRepo.h"

namespace Configs {
    WarpExitRepo::WarpExitRepo(Database &database) : db(database) {
        createTables();
    }

    void WarpExitRepo::createTables() const {
        db.exec(R"(
            CREATE TABLE IF NOT EXISTS warp_exit_blacklist (
                ip TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )
        )");
        db.exec(R"(
            CREATE TABLE IF NOT EXISTS warp_endpoint_exit (
                endpoint TEXT PRIMARY KEY,
                exit_ip TEXT NOT NULL,
                learned_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )
        )");
    }

    QList<WarpExitEntry> WarpExitRepo::Blacklist() const {
        QList<WarpExitEntry> list;
        auto query = db.query("SELECT ip, enabled FROM warp_exit_blacklist ORDER BY ip");
        if (!query) return list;
        while (query->executeStep()) {
            list.append({QString::fromStdString(query->getColumn(0).getString()), query->getColumn(1).getInt() != 0});
        }
        return list;
    }

    bool WarpExitRepo::AddToBlacklist(const QString &ip) {
        return db.execChanges("INSERT OR IGNORE INTO warp_exit_blacklist (ip) VALUES (?)", ip.toStdString()) > 0;
    }

    void WarpExitRepo::SetEnabled(const QString &ip, bool enabled) {
        db.exec("UPDATE warp_exit_blacklist SET enabled = ? WHERE ip = ?", enabled ? 1 : 0, ip.toStdString());
    }

    void WarpExitRepo::RemoveFromBlacklist(const QString &ip) {
        db.exec("DELETE FROM warp_exit_blacklist WHERE ip = ?", ip.toStdString());
    }

    bool WarpExitRepo::IsBlocked(const QString &ip) const {
        auto query = db.query("SELECT 1 FROM warp_exit_blacklist WHERE ip = ? AND enabled = 1", ip.toStdString());
        return query && query->executeStep();
    }

    QString WarpExitRepo::LearnedExit(const QString &endpoint) const {
        auto query = db.query("SELECT exit_ip FROM warp_endpoint_exit WHERE endpoint = ?", endpoint.toStdString());
        if (!query || !query->executeStep()) return {};
        return QString::fromStdString(query->getColumn(0).getString());
    }

    void WarpExitRepo::LearnExit(const QString &endpoint, const QString &exitIp) {
        db.exec("INSERT INTO warp_endpoint_exit (endpoint, exit_ip, learned_at) VALUES (?, ?, strftime('%s', 'now')) "
                "ON CONFLICT(endpoint) DO UPDATE SET exit_ip = excluded.exit_ip, learned_at = excluded.learned_at",
                endpoint.toStdString(), exitIp.toStdString());
    }
}
