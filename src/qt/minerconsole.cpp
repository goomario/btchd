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
#include <chainparamsbase.h>
#include <util.h>

#include <QDesktopWidget>
#include <QFile>
#include <QFileDialog>
#include <QMessageBox>
#include <QSettings>
#include <QStringList>
#include <QTemporaryFile>
#include <QTextStream>
#include <qt/minerconsole.moc>

namespace {
 
 const char passphraseSettingsKey[] = "MinerPassphrase";
 const char targetDeadlineSettingsKey[] = "MinerTargetDeadline";
 const char plotfilesSettingsKey[] = "MinerPlotfiles";

 const char creepMinerRelativePath[] = "../../miner";

}

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

    // Load config
    ui->passphraseLineEdit->setText(settings.value(passphraseSettingsKey,"").toString());
    ui->targetDeadlineLineEdit->setText(settings.value(targetDeadlineSettingsKey, "").toString());
    ui->plotfileList->addItems(settings.value(plotfilesSettingsKey, "").toStringList());
    for (int i = 0; i < ui->plotfileList->count(); ) {
        if (ui->plotfileList->item(i)->text().trimmed().isEmpty()) {
            delete ui->plotfileList->takeItem(i);
        } else {
            i++;
        }
    }

    // Update mining status
    notifyMiningStatusChange(mining);
}

MinerConsole::~MinerConsole()
{
    QSettings settings;
    settings.setValue("MinerConsoleWindowGeometry", saveGeometry());
    
    saveSettings();

    minerConfigFile.reset();

    delete ui;
}

void MinerConsole::notifyMiningStatusChange(bool mining)
{
    this->mining = mining;

    ui->switchMiningButton->setText(mining ? tr("Stop mining") : tr("Start mining"));
    ui->addPlotFileButton->setEnabled(!this->mining);
    ui->removePlotFileButton->setEnabled(!this->mining);
    ui->passphraseLineEdit->setReadOnly(!this->mining);
    ui->targetDeadlineLineEdit->setReadOnly(!this->mining);

    if (mining) {
        saveSettings();
    }
}

void MinerConsole::saveSettings()
{
    QSettings settings;
    settings.setValue(passphraseSettingsKey, ui->passphraseLineEdit->text());
    settings.setValue(targetDeadlineSettingsKey, ui->targetDeadlineLineEdit->text());

    QStringList plotfiles;
    for (int i = 0; i < ui->plotfileList->count(); i++) {
        plotfiles.append(ui->plotfileList->item(i)->text());
    }
    settings.setValue(plotfilesSettingsKey, plotfiles);
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

    // update setting
    QSettings settings;
    QStringList plotfiles;
    for (int i = 0; i < ui->plotfileList->count(); i++) {
        plotfiles.append(ui->plotfileList->item(i)->text());
    }
    settings.setValue(plotfilesSettingsKey, plotfiles);
}

void MinerConsole::on_removePlotFileButton_clicked()
{
    int row = ui->plotfileList->currentRow();
    if (row != -1) {
        delete ui->plotfileList->takeItem(row);

        // update setting
        QSettings settings;
        QStringList plotfiles;
        for (int i = 0; i < ui->plotfileList->count(); i++) {
            plotfiles.append(ui->plotfileList->item(i)->text());
        }
        settings.setValue(plotfilesSettingsKey, plotfiles);
    }
}

void MinerConsole::on_switchMiningButton_clicked()
{
    if (mining) {
        // Stop mining
        mining = false;

        minerConfigFile.reset();
    } else {
        // Start mining

        // template file
        QString configContent;
        {
            QString tplfilepath((GetAppDir() / creepMinerRelativePath / "mining.conf.tpl").c_str());
            LogPrintf("%s: Template file %s\n", __func__, tplfilepath.toStdString().c_str());
            QFile tplfile(tplfilepath);
            if (!tplfile.open(QFile::ReadOnly | QFile::Text)) {
                QMessageBox::critical(this, "Error", QString("Error: Cannot read miner default configuration file!"));
                return;
            }
            configContent = QTextStream(&tplfile).readAll();
        }

        // replace configuration
        {
            QStringList plotfiles;
            for (int i = 0; i < ui->plotfileList->count(); i++) {
                plotfiles.append(ui->plotfileList->item(i)->text());
            }

            configContent = configContent
                .replace("${passphrase}", ui->passphraseLineEdit->text())
                .replace("${targetDeadline}", ui->targetDeadlineLineEdit->text())
                .replace("${miningInfo}", QString("http://localhost:") + QString::number(BaseParams().RPCPort()) + QString("/burst"))
                .replace("${submission}", QString("http://localhost:") + QString::number(BaseParams().RPCPort()) + QString("/burst"))
                .replace("${plots}", QString("\"") + plotfiles.join("\",\"") + QString("\""));

            LogPrintf("%s: configuration content \n%s\n", __func__, configContent.toStdString().c_str());
        }
        // temporary
        {
            minerConfigFile = std::make_shared<QTemporaryFile>();
            if (!minerConfigFile || !minerConfigFile->open()) {
                minerConfigFile.reset();
                QMessageBox::critical(this, "Error", QString("Error: Cannot create miner configuration file!"));
                return;
            }
            QTextStream(minerConfigFile.get()) << configContent;

            LogPrintf("%s: Temporary configuration file %s\n", __func__, minerConfigFile->fileName().toStdString().c_str());
        }

        // run miner

        mining = true;

    }

    notifyMiningStatusChange(mining);
}