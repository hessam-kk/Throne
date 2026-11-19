#pragma once

#include <QDialog>

class QLabel;
class QLineEdit;
class QListWidget;
class QPushButton;

// Exit IPs that must not be used as the WARP second hop. A checked entry is refused; an unchecked one is kept for later.
// Kept out of the Routing Settings window so it can stay open while a rotation runs.
class DialogWarpBlacklist final : public QDialog {
    Q_OBJECT

public:
    explicit DialogWarpBlacklist(QWidget *parent = nullptr);

private:
    void reload();
    void addEntry();
    void removeSelected();
    void syncEditable();

    QListWidget *list = nullptr;
    QLineEdit *input = nullptr;
    QPushButton *addButton = nullptr;
    QPushButton *removeButton = nullptr;
    QLabel *status = nullptr;
    bool reloading = false;
};
