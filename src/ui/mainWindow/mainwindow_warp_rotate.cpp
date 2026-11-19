#include "include/ui/mainwindow.h"

#include "include/database/DatabaseManager.h"
#include "include/engine/services/WarpRotationService.h"
#include "include/global/Notice.hpp"
#include "include/global/Utils.hpp"
#include "include/ui/setting/dialog_warp_blacklist.h"

void MainWindow::setupWarpFooter() {
    auto *rotation = Engine::WarpRotationService::instance();

    // After label_running: the active config name stays first, the WARP actions follow it at the bottom left.
    warpRotateButton = new QToolButton(this);
    warpRotateButton->setText(tr("Rotate IP"));
    warpRotateButton->setToolTip(tr("Blacklist the current WARP exit IP and switch to another scanned endpoint"));
    warpRotateButton->setToolButtonStyle(Qt::ToolButtonTextOnly);
    warpRotateButton->setAutoRaise(true);
    ui->horizontalLayout->insertWidget(1, warpRotateButton);

    warpBlacklistButton = new QToolButton(this);
    warpBlacklistButton->setText(tr("Blacklist"));
    warpBlacklistButton->setToolTip(tr("Choose which WARP exit IPs must never be used"));
    warpBlacklistButton->setToolButtonStyle(Qt::ToolButtonTextOnly);
    warpBlacklistButton->setAutoRaise(true);
    ui->horizontalLayout->insertWidget(2, warpBlacklistButton);

    connect(warpRotateButton, &QToolButton::clicked, this, [rotation] { rotation->rotate(); });
    connect(warpBlacklistButton, &QToolButton::clicked, this, &MainWindow::openWarpBlacklist);
    connect(rotation, &Engine::WarpRotationService::stateChanged, this, &MainWindow::refreshWarpFooter);
    connect(rotation, &Engine::WarpRotationService::finished, this, [this](bool ok, const QString &message) {
        if (message.isEmpty()) return;
        MW_show_log(QStringLiteral("[WARP] ") + message);
        if (!ok) PostNotice({NoticeLevel::Warning, tr("Rotate IP"), message});
    });

    refreshWarpFooter();
}

void MainWindow::refreshWarpFooter() {
    if (warpRotateButton == nullptr || warpBlacklistButton == nullptr) return;
    const auto *settings = Configs::dataManager->settingsRepo.get();
    // WARP outranks nothing: when Tor is the exit, WARP's endpoint is not in the chain at all.
    const bool warpOn = settings->enable_warp && !settings->enable_tor;
    warpRotateButton->setVisible(warpOn);
    warpBlacklistButton->setVisible(warpOn);
    if (!warpOn) return;

    const bool busy = Engine::WarpRotationService::instance()->rotating();
    warpRotateButton->setEnabled(!busy);
    warpRotateButton->setText(busy ? tr("Rotating...") : tr("Rotate IP"));
}

void MainWindow::openWarpBlacklist() {
    if (m_warpBlacklistDialog != nullptr) {
        m_warpBlacklistDialog->raise();
        m_warpBlacklistDialog->activateWindow();
        return;
    }
    auto *dialog = new DialogWarpBlacklist(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    connect(dialog, &QObject::destroyed, this, [this] { m_warpBlacklistDialog = nullptr; });
    m_warpBlacklistDialog = dialog;
    dialog->show();
}
