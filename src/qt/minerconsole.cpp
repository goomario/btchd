// Copyright (c) 2017-2018 The Bitcoin Ore developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/minerconsole.h>

#include <qt/forms/ui_minerwindow.h>
#include <qt/platformstyle.h>

#include <chainparams.h>

#include <QDesktopWidget>
#include <QFileDialog>
#include <QMessageBox>
#include <QSettings>

#include <qt/minerconsole.moc>

MinerConsole::MinerConsole(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::MinerConsole),
    mining(false)
{
    ui->setupUi(this);

    QSettings settings;
    if (!restoreGeometry(settings.value("MinerConsoleWindowGeometry").toByteArray())) {
        // Restore failed (perhaps missing setting), center the window
        move(QApplication::desktop()->availableGeometry().center() - frameGeometry().center());
    }

    connect(ui->plotfileList, SIGNAL(currentRowChanged(int)), this, SLOT(on_plotfileList_itemSelectionChanged(int)));

    notifyMiningStatusChange(mining);
}

MinerConsole::~MinerConsole()
{
    QSettings settings;
    settings.setValue("MinerConsoleWindowGeometry", saveGeometry());

    delete ui;
}

void MinerConsole::notifyMiningStatusChange(bool mining)
{
    this->mining = mining;

    ui->switchMiningButton->setText(mining ? tr("Stop mining") : tr("Start mining"));
    ui->plotfileList->setEnabled(!this->mining);
    ui->addPlotFileButton->setEnabled(!this->mining);
    ui->removePlotFileButton->setEnabled(!this->mining);
    ui->passphareLineEdit->setEnabled(!this->mining);
    ui->plotfileList->setEnabled(!this->mining);
}

void MinerConsole::on_plotfileList_itemSelectionChanged(int row)
{
    ui->removePlotFileButton->setEnabled(row != -1);
}

void MinerConsole::on_addPlotFileButton_clicked()
{
    QString path = QFileDialog::getOpenFileName(this, tr("Add Plot File"), ".", tr("Plot File(*)"));
    if (path.size() == 0) {
        return;
    }

    ui->plotfileList->addItem(path);
    ui->plotfileList->setCurrentRow(ui->plotfileList->count() - 1);
}

void MinerConsole::on_removePlotFileButton_clicked()
{
    int row = ui->plotfileList->currentRow();
    if (row != -1) {
        delete ui->plotfileList->takeItem(row);
    }
}

void MinerConsole::on_switchMiningButton_clicked()
{
    if (mining) {
        // Stop mining
        mining = false;
    } else {
        // Start mining

        mining = true;
    }

    notifyMiningStatusChange(mining);
}