#include "include/ui/setting/dialog_warp_blacklist.h"

#include "include/engine/services/WarpRotationService.h"

#include <QAbstractItemView>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>

DialogWarpBlacklist::DialogWarpBlacklist(QWidget *parent) : QDialog(parent) {
    setWindowTitle(tr("WARP Exit IP Blacklist"));
    resize(420, 380);

    auto *layout = new QVBoxLayout(this);

    auto *hint = new QLabel(tr("A checked IP is never used as the WARP exit. Unchecked entries are kept but ignored, "
                               "so you can re-enable an IP once it works again."),
                            this);
    hint->setWordWrap(true);
    layout->addWidget(hint);

    list = new QListWidget(this);
    list->setSelectionMode(QAbstractItemView::SingleSelection);
    layout->addWidget(list, 1);

    auto *addRow = new QHBoxLayout;
    input = new QLineEdit(this);
    input->setPlaceholderText(tr("Exit IP, for example 104.28.0.1"));
    addButton = new QPushButton(tr("Add"), this);
    addRow->addWidget(input, 1);
    addRow->addWidget(addButton);
    layout->addLayout(addRow);

    status = new QLabel(this);
    status->setWordWrap(true);
    layout->addWidget(status);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    removeButton = buttons->addButton(tr("Remove"), QDialogButtonBox::ActionRole);
    layout->addWidget(buttons);

    connect(addButton, &QPushButton::clicked, this, &DialogWarpBlacklist::addEntry);
    connect(input, &QLineEdit::returnPressed, this, &DialogWarpBlacklist::addEntry);
    connect(removeButton, &QPushButton::clicked, this, &DialogWarpBlacklist::removeSelected);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(list, &QListWidget::itemChanged, this, [this](QListWidgetItem *item) {
        if (reloading || item == nullptr) return;
        Engine::WarpRotationService::instance()->setBlacklisted(item->data(Qt::UserRole).toString(),
                                                                 item->checkState() == Qt::Checked);
    });

    auto *rotation = Engine::WarpRotationService::instance();
    connect(rotation, &Engine::WarpRotationService::blacklistChanged, this, &DialogWarpBlacklist::reload);
    connect(rotation, &Engine::WarpRotationService::stateChanged, this, &DialogWarpBlacklist::syncEditable);

    reload();
    syncEditable();
}

void DialogWarpBlacklist::reload() {
    reloading = true;
    list->clear();
    for (const auto &entry : Engine::WarpRotationService::instance()->blacklist()) {
        auto *item = new QListWidgetItem(entry.ip, list);
        item->setData(Qt::UserRole, entry.ip);
        item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
        item->setCheckState(entry.enabled ? Qt::Checked : Qt::Unchecked);
    }
    reloading = false;
    status->clear();
}

void DialogWarpBlacklist::addEntry() {
    const auto ip = input->text().trimmed();
    if (ip.isEmpty()) return;
    if (const auto error = Engine::WarpRotationService::instance()->addToBlacklist(ip); !error.isEmpty()) {
        status->setText(error);
        return;
    }
    input->clear();
}

void DialogWarpBlacklist::removeSelected() {
    const auto *item = list->currentItem();
    if (item == nullptr) {
        status->setText(tr("Select an entry to remove"));
        return;
    }
    Engine::WarpRotationService::instance()->removeFromBlacklist(item->data(Qt::UserRole).toString());
}

void DialogWarpBlacklist::syncEditable() {
    // A rotation rewrites the endpoint underneath the list, so no edit may race it.
    const bool busy = Engine::WarpRotationService::instance()->rotating();
    input->setEnabled(!busy);
    addButton->setEnabled(!busy);
    removeButton->setEnabled(!busy);
    list->setEnabled(!busy);
}
