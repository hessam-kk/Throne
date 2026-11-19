#pragma once

#include "Database.h"

#include <QList>
#include <QString>

namespace Configs {
    struct WarpExitEntry {
        // Canonical IPv4 or IPv6 address.
        QString ip;
        bool enabled = true;
    };

    // Exit IPs the user no longer wants WARP to land on, and the exit IP last observed behind each WARP endpoint.
    // Both survive restarts; the learning table is a cache that a rotation reads before it dials an endpoint.
    class WarpExitRepo {
    private:
        Database &db;

        void createTables() const;

    public:
        explicit WarpExitRepo(Database &database);

        [[nodiscard]] QList<WarpExitEntry> Blacklist() const;

        // False when the address is already listed; SetEnabled is how a disabled entry comes back.
        bool AddToBlacklist(const QString &ip);

        void SetEnabled(const QString &ip, bool enabled);

        void RemoveFromBlacklist(const QString &ip);

        [[nodiscard]] bool IsBlocked(const QString &ip) const;

        // Empty when the endpoint was never observed.
        [[nodiscard]] QString LearnedExit(const QString &endpoint) const;

        void LearnExit(const QString &endpoint, const QString &exitIp);
    };
}
