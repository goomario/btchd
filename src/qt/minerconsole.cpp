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
#include <QScrollBar>
#include <QSettings>
#include <QStringList>
#include <QTemporaryFile>
#include <QTextStream>

#include <qt/minerconsole.moc>

namespace {
 
const char passphraseSettingsKey[] = "MinerPassphrase";
const char targetDeadlineSettingsKey[] = "MinerTargetDeadline";
const char plotfilesSettingsKey[] = "MinerPlotfiles";

const char creepMinerRelativePath[] = "tools/creepMiner";
}

MinerConsole::MinerConsole(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::MinerConsole)
{
    ui->setupUi(this);
    ui->removePlotFileButton->setEnabled(false);

    QSettings settings;
    if (!restoreGeometry(settings.value("MinerConsoleWindowGeometry").toByteArray())) {
        // Restore failed (perhaps missing setting), center the window
        move(QApplication::desktop()->availableGeometry().center() - frameGeometry().center());
    }

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
    notifyMiningStatusChanged(false);

    minerProcess = std::unique_ptr<QProcess>(new QProcess());
    connect(minerProcess.get(), SIGNAL(started()), this, SLOT(onMiningStarted()));
    connect(minerProcess.get(), SIGNAL(finished(int, QProcess::ExitStatus)), this, SLOT(onMiningFinished(int, QProcess::ExitStatus)));
    connect(minerProcess.get(), SIGNAL(readyReadStandardOutput()), this, SLOT(onMiningReadyReadStandardOutput()));
    connect(minerProcess.get(), SIGNAL(readyReadStandardError()), this, SLOT(onMiningReadyReadStandardError()));
}

MinerConsole::~MinerConsole()
{
    QSettings settings;
    settings.setValue("MinerConsoleWindowGeometry", saveGeometry());
    
    saveSettings();

    minerProcess.reset();
    minerConfigFile.reset();

    delete ui;
}

void MinerConsole::notifyMiningStatusChanged(bool mining)
{
    ui->switchMiningButton->setText(mining ? tr("Stop mining") : tr("Start mining"));
    ui->addPlotFileButton->setEnabled(!mining);
    ui->removePlotFileButton->setEnabled(!mining);
    ui->passphraseLineEdit->setReadOnly(mining);
    ui->targetDeadlineLineEdit->setReadOnly(mining);

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

void MinerConsole::appendLog(const QStringList &lines)
{
    // https://stackoverflow.com/questions/13559990/how-to-append-text-to-qplaintextedit-without-adding-newline-and-keep-scroll-at
    QScrollBar *scrollbar = ui->logPlainTextEdit->verticalScrollBar();
    bool atBottom = (scrollbar->value() == scrollbar->maximum());

    QTextCursor cursor(ui->logPlainTextEdit->document());
    cursor.beginEditBlock();
    cursor.movePosition(QTextCursor::End);
    for (int i = 0; i < lines.size(); i++) {
        cursor.insertText(lines.at(i));
        if (i + 1 < lines.size())
            cursor.insertBlock();
    }
    cursor.endEditBlock();

    if (atBottom) {
        scrollbar->setValue(scrollbar->maximum());
    }
}

void MinerConsole::close()
{
    QWidget::close();

    if (minerProcess->state() != QProcess::NotRunning) {
        minerProcess->kill();
    }
    minerConfigFile.reset();
}

void MinerConsole::on_plotfileList_itemSelectionChanged()
{
    if (minerProcess->state() == QProcess::NotRunning) {
        ui->removePlotFileButton->setEnabled(ui->plotfileList->currentRow() != -1);
    }
}

void MinerConsole::on_addPlotFileButton_clicked()
{
    QString path = QFileDialog::getOpenFileName(this, tr("Add Plot File"), ".", tr("Plot File(*)"));
    if (path.isEmpty()) {
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
    if (minerProcess->state() == QProcess::NotRunning) {
        // Start mining
        if (ui->passphraseLineEdit->text().isEmpty()) {
            QMessageBox::information(this, tr("Miner console"), QString(tr("Please input your passphare!")));
            return;
        }
        if (ui->plotfileList->count() == 0) {
            QMessageBox::information(this, tr("Miner console"), QString(tr("Please add your plot files!")));
            return;
        }

        {
            // template file
            QString configContent;
#ifdef WIN32
            QString tplfilepath = QString::fromWCharArray((GetAppDir() / creepMinerRelativePath / "mining.conf.tpl").c_str());
#else
            QString tplfilepath = QString((GetAppDir() / creepMinerRelativePath / "mining.conf.tpl").c_str());
#endif
            LogPrintf("%s: Template file %s\n", __func__, tplfilepath.toStdString().c_str());
            QFile tplfile(tplfilepath);
            if (!tplfile.open(QFile::ReadOnly | QFile::Text)) {
                QMessageBox::critical(this, tr("Miner console"), QString(tr("Error: Cannot read miner default configuration file!")));
                return;
            }
            configContent = QTextStream(&tplfile).readAll();

            // replace configuration
            QStringList plotfiles;
            for (int i = 0; i < ui->plotfileList->count(); i++) {
                plotfiles.append(ui->plotfileList->item(i)->text());
            }

            configContent = configContent
                .replace("${passphrase}", ui->passphraseLineEdit->text())
                .replace("${targetDeadline}", ui->targetDeadlineLineEdit->text())
                .replace("${miningInfo}", QString("http://127.0.0.1:") + QString::number(BaseParams().RPCPort()) + QString("/burst"))
                .replace("${submission}", QString("http://127.0.0.1:") + QString::number(BaseParams().RPCPort()) + QString("/burst"))
                .replace("${plots}", QString("\"") + plotfiles.join("\",\"") + QString("\""));

            LogPrint(BCLog::POC, "%s: configuration content \n%s\n", __func__, configContent.toStdString().c_str());
            // temporary
            minerConfigFile = std::unique_ptr<QTemporaryFile>(new QTemporaryFile());
            if (!minerConfigFile || !minerConfigFile->open()) {
                minerConfigFile.reset();
                QMessageBox::critical(this, tr("Error"), QString(tr("Error: Cannot create miner configuration file!")));
                return;
            }
            QTextStream(minerConfigFile.get()) << configContent;
            minerConfigFile->flush();

            LogPrintf("%s: Temporary configuration file %s\n", __func__, minerConfigFile->fileName().toStdString().c_str());
        }

        // run miner
        {
            ui->switchMiningButton->setEnabled(false);

#ifdef WIN32
            const QString creepMinerDir = QString::fromWCharArray((GetAppDir() / creepMinerRelativePath).c_str());
            const QString creepMinerFile = "creepMiner.exe";
            const QStringList arguments = QStringList() << "/config" << minerConfigFile->fileName();
#else
            const QString creepMinerDir = QString((GetAppDir() / creepMinerRelativePath).c_str());
            const QString creepMinerFile = "creepMiner";
            const QStringList arguments = QStringList() << "--config" << minerConfigFile->fileName();
#endif
            minerProcess->setWorkingDirectory(creepMinerDir);
            minerProcess->start(creepMinerDir + "/" + creepMinerFile, arguments, QProcess::ReadOnly);
        }
    } else {
        // Stop mining
        ui->switchMiningButton->setEnabled(false);
        minerProcess->kill();
        minerConfigFile.reset();
    }
}

void MinerConsole::onMiningStarted()
{
    notifyMiningStatusChanged(true);
    ui->switchMiningButton->setEnabled(true);

    ui->logPlainTextEdit->clear();
    appendLog(QStringList() << QString("Start miner") << "" << "");
}

void MinerConsole::onMiningFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    notifyMiningStatusChanged(false);
    ui->switchMiningButton->setEnabled(true);

    appendLog(QStringList() << "" << "" << QString("Stop miner (") + QString::number((int)exitStatus) + QString(")"));
}

void MinerConsole::onMiningReadyReadStandardOutput()
{
    appendLog(QString(minerProcess->readAllStandardOutput()).replace("\r\n","\n").split("\n"));
}

void MinerConsole::onMiningReadyReadStandardError()
{
    appendLog(QString(minerProcess->readAllStandardError()).replace("\r\n", "\n").split("\n"));
}
