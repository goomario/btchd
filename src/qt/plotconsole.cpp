// Copyright (c) 2017-2018 The BCO Ore developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/plotconsole.h>

#include <qt/forms/ui_plotwindow.h>
#include <qt/platformstyle.h>

#include <chainparams.h>
#include <chainparamsbase.h>
#include "poc/passphrase.h"
#include <poc/poc.h>
#include <util.h>

#include <QDesktopWidget>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QMessageBox>
#include <QRegExp>
#include <QScrollBar>
#include <QSettings>
#include <QStorageInfo>
#include <QStringList>
#include <QTemporaryFile>

namespace {

const char passphraseSettingsKey[] = "PlotPassphrase";
const char startNonceSettingsKey[] = "PlotStartNonce";
const char noncesSettingsKey[] = "PlotNonces";
const char threadNumberSettingsKey[] = "PlotThreadNumber";
const char memoryGBSettingsKey[] = "PlotMemoryGB";
const char folderSettingsKey[] = "PlotFileFolder";

const char xplotterRelativePath[] = "tools/xplotter";
}

PlotConsole::PlotConsole(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PlotConsole),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);
    connect(ui->noncesSpinBox, SIGNAL(valueChanged(int)), this, SLOT(on_plotParamSpinBox_changed(int)));
    connect(ui->passphraseEdit->document(), SIGNAL(contentsChanged()), this, SLOT(on_passphraseEdit_changed()));

    QSettings settings;
    if (!restoreGeometry(settings.value("PlotConsoleWindowGeometry").toByteArray())) {
        // Restore failed (perhaps missing setting), center the window
        move(QApplication::desktop()->availableGeometry().center() - frameGeometry().center());
    }

    // Load config
    ui->passphraseEdit->document()->setPlainText(settings.value(passphraseSettingsKey,"").toString());
    ui->startNonceSpinBox->setValue(settings.value(startNonceSettingsKey, "0").toInt());
    ui->noncesSpinBox->setValue(settings.value(noncesSettingsKey, "1").toInt());
    ui->threadsSpinBox->setValue(settings.value(threadNumberSettingsKey, "4").toInt());
    ui->memoryGBSpinBox->setValue(settings.value(memoryGBSettingsKey, "1").toInt());
    ui->plotfolderLineEdit->setText(settings.value(folderSettingsKey, "").toString());

    plotProcess = std::unique_ptr<QProcess>(new QProcess());
    connect(plotProcess.get(), SIGNAL(started()), this, SLOT(onPlotStarted()));
    connect(plotProcess.get(), SIGNAL(finished(int, QProcess::ExitStatus)), this, SLOT(onPlotFinished(int, QProcess::ExitStatus)));
    connect(plotProcess.get(), SIGNAL(readyReadStandardOutput()), this, SLOT(onPlotReadyReadStandardOutput()));
    connect(plotProcess.get(), SIGNAL(readyReadStandardError()), this, SLOT(onPlotReadyReadStandardError()));

    on_togglePassphraseButton_clicked(); // default set to hide

    // Update mining status
    notifyPlotStatusChanged(false);

    updatePlotInfo();
}

PlotConsole::~PlotConsole()
{
    QSettings settings;
    settings.setValue("PlotConsoleWindowGeometry", saveGeometry());
    
    saveSettings();

    plotProcess.reset();

    delete ui;
}

void PlotConsole::notifyPlotStatusChanged(bool plotting)
{
    ui->startPlotButton->setText(plotting ? tr("Stop plot") : tr("Start plot"));
    ui->passphraseEdit->setReadOnly(plotting || !isShowPassphrase());
    ui->threadsSpinBox->setEnabled(!plotting);
    ui->startNonceSpinBox->setEnabled(!plotting);
    ui->noncesSpinBox->setEnabled(!plotting);
    ui->memoryGBSpinBox->setEnabled(!plotting);
    ui->plotfolderLineEdit->setEnabled(!plotting);
    ui->setPlotPathButton->setEnabled(!plotting);
    ui->togglePassphraseButton->setEnabled(!plotting);
    ui->genPassphraseButton->setEnabled(!plotting);

    if (plotting) {
        if (isShowPassphrase()) on_togglePassphraseButton_clicked();

        saveSettings();
    }
}

void PlotConsole::saveSettings()
{
    QSettings settings;
    settings.setValue(passphraseSettingsKey, passphrase);
    settings.setValue(startNonceSettingsKey, ui->startNonceSpinBox->value());
    settings.setValue(noncesSettingsKey, ui->noncesSpinBox->value());
    settings.setValue(threadNumberSettingsKey, ui->threadsSpinBox->value());
    settings.setValue(memoryGBSettingsKey, ui->memoryGBSpinBox->value());
    settings.setValue(folderSettingsKey, ui->plotfolderLineEdit->text());
}

void PlotConsole::appendLog(const QStringList &lines)
{
    int updateProgress = -1;

    QScrollBar *scrollbar = ui->logPlainTextEdit->verticalScrollBar();
    bool atBottom = (scrollbar->value() == scrollbar->maximum());

    QTextCursor cursor(ui->logPlainTextEdit->document());
    cursor.beginEditBlock();
    cursor.movePosition(QTextCursor::End);
    for (int i = 0; i < lines.size(); i++) {
        const QString &line = lines.at(i);
        cursor.insertText(line);
        if (i + 1 < lines.size())
            cursor.insertBlock();

        // progress
        int start, end = line.lastIndexOf("%] Generating nonces from");
        for (start = end - 1; start > 0 && line[start] != '['; start--);
        if (start >= 0 && end > start + 1) {
            bool ok;
            float fProgress = line.mid(start + 1, end - start - 1).toFloat(&ok);
            if (ok) {
                updateProgress = static_cast<int>(fProgress);
            }
        }
    }
    cursor.endEditBlock();

    if (atBottom) {
        scrollbar->setValue(scrollbar->maximum());
    }

    if (updateProgress >= 0 && updateProgress <= 100) {
        ui->plotProgressBar->setValue(updateProgress);
    }
}

void PlotConsole::updatePlotInfo()
{
    QString info;

    // Account
    if (!passphrase.isEmpty()) {
        info += tr("The Passphrase Digital ID: %1.").arg((uint64_t)poc::GetAccountIdByPassPhrase(passphrase.toUtf8().constData())) + "\n";
    }

    // plot file size
    int64_t requireByteSize = ui->noncesSpinBox->value() * 256LL * 1024; // 256KB
    info += tr("The plot file size: %1GB.").arg(1.0f * requireByteSize / 1024 / 1024 / 1024, 5, 'f', 2) + "\n";

    // validate space
    if (!ui->plotfolderLineEdit->text().isEmpty() && QDir(ui->plotfolderLineEdit->text()).exists()) {
        int64_t availableByteSize = (int64_t)QStorageInfo(ui->plotfolderLineEdit->text()).bytesAvailable();
        info += tr("The destination folder free size: %1GB.").arg(1.0f * availableByteSize / 1024 / 1024 / 1024, 5, 'f', 2) + "\n";
        if (availableByteSize < requireByteSize) {
            info += tr("This folder free size not enough!") + "\n";
            info += tr("This folder max nonce number: %1.").arg((availableByteSize - 32 * 1024 * 1024) / (256LL*1024)) + "\n"; // reserved 32MB
        }
    } else {
        info += tr("Please select exist directory to save this plot file!") + "\n";
    }
    

    ui->plotinfoLabel->setText(info);
}

bool PlotConsole::isShowPassphrase()
{
    return passphrase == ui->passphraseEdit->document()->toPlainText();
}

void PlotConsole::on_plotParamSpinBox_changed(int)
{
    updatePlotInfo();
}

void PlotConsole::close()
{
    QWidget::close();

    if (plotProcess->state() != QProcess::NotRunning) {
        plotProcess->kill();
    }
}

void PlotConsole::on_passphraseEdit_changed()
{
    QString text = ui->passphraseEdit->document()->toPlainText();
    if (text.isEmpty()) {
        // clear. not readonly
        passphrase = "";
        updatePlotInfo();
    } else if (text != QString(std::string(text.length(), '*').c_str())) {
        // passphrase
        passphrase = text;
        updatePlotInfo();
    } else {
        // set to "**********"
        // ignore this text
    }
}

void PlotConsole::on_togglePassphraseButton_clicked()
{
    if (!passphrase.isEmpty() && isShowPassphrase()) {
        // hide, next action is show
        ui->passphraseEdit->document()->setPlainText(QString(std::string(passphrase.length(), '*').c_str()));
        ui->passphraseEdit->setReadOnly(true);
        ui->togglePassphraseButton->setIcon(platformStyle->SingleColorIcon(":/icons/eye"));
        ui->togglePassphraseButton->setToolTip(tr("Show passphrase."));
    } else {
        // show, next action is hide
        ui->passphraseEdit->document()->setPlainText(passphrase);
        ui->passphraseEdit->setReadOnly(false);
        ui->togglePassphraseButton->setIcon(platformStyle->SingleColorIcon(":/icons/eye_close"));
        ui->togglePassphraseButton->setToolTip(tr("Hide passphrase."));
    }
}

void PlotConsole::on_genPassphraseButton_clicked()
{
    if (!isShowPassphrase())
        on_togglePassphraseButton_clicked();

    ui->passphraseEdit->document()->setPlainText(QString(poc::generatePassPhrase().c_str()));
    ui->passphraseEdit->selectAll();

    saveSettings();

    QMessageBox::warning(this, tr("Plot console"), QString(tr("Please remeber your passphrase.")));
}

void PlotConsole::on_setPlotPathButton_clicked()
{
    QString folder = QFileDialog::getExistingDirectory(this, tr("Select plot folder"), tr("plots"));
    if (folder.isEmpty()) {
        return;
    }

    ui->plotfolderLineEdit->setText(folder);

    updatePlotInfo();
    saveSettings();
}

void PlotConsole::on_startPlotButton_clicked()
{
    if (plotProcess->state() == QProcess::NotRunning) {
        // Start plot
        if (passphrase.isEmpty() || !QRegExp("^[a-z\\ ]{20,256}$").exactMatch(passphrase)) {
            ui->passphraseEdit->setStyleSheet("QPlainTextEdit { color: red; }");
            QMessageBox::information(this, tr("Plot console"),
                QString(tr("Can only contain lowercase letters and spaces, and is between 20 and 255 characters.")));
            return;
        }
        ui->passphraseEdit->setStyleSheet("");

        if (ui->plotfolderLineEdit->text().isEmpty() || !QDir(ui->plotfolderLineEdit->text()).exists()) {
            ui->plotfolderLineEdit->setStyleSheet("QLineEdit { color: red; }");
            QMessageBox::information(this, tr("Plot console"), QString(tr("Please select exist directory to save this plot file!")));
            return;
        }
        ui->plotfolderLineEdit->setStyleSheet("");

        ui->startPlotButton->setEnabled(false);

#ifdef WIN32
        const QString xplotterDir = QString::fromWCharArray((GetAppDir() / xplotterRelativePath).c_str());
        const QString xplotterFile = "XPlotter_sse.exe";
#else
        const QString xplotterDir = QString((GetAppDir() / xplotterRelativePath).c_str());
        const QString xplotterFile = "XPlotter_sse";
#endif
        if (QFileInfo(xplotterDir + "/" + xplotterFile).exists()) {
            const QStringList arguments = QStringList() 
                << "-id" << QString::number(poc::GetAccountIdByPassPhrase(passphrase.toStdString()))
                << "-sn" << QString::number(ui->startNonceSpinBox->value())
                << "-n" << QString::number(ui->noncesSpinBox->value())
                << "-t" << QString::number(ui->threadsSpinBox->value())
                << "-mem" << QString::number(ui->memoryGBSpinBox->value()) + "G"
                << "-path" << ui->plotfolderLineEdit->text() + "/";

            plotProcess->setWorkingDirectory(xplotterDir);
            plotProcess->start(xplotterDir + "/" + xplotterFile, arguments, QProcess::ReadOnly);
        } else {
            ui->startPlotButton->setEnabled(true);
        }
    } else {
        // Stop plot
        ui->startPlotButton->setEnabled(false);
        plotProcess->kill();
    }
}

void PlotConsole::onPlotStarted()
{
    notifyPlotStatusChanged(true);
    ui->startPlotButton->setEnabled(true);
    ui->plotProgressBar->setValue(0);

    ui->logPlainTextEdit->clear();
    appendLog(QStringList() << QString("Start plot") << "" << "");
}

void PlotConsole::onPlotFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    notifyPlotStatusChanged(false);
    ui->startPlotButton->setEnabled(true);
    ui->plotProgressBar->setValue(100);

    appendLog(QStringList() << "" << "" << QString("Stop plot (") + QString::number((int)exitStatus) + QString(")"));
}

void PlotConsole::onPlotReadyReadStandardOutput()
{
    appendLog(QString(plotProcess->readAllStandardOutput()).replace("\r\n", "\n").split("\n"));
}

void PlotConsole::onPlotReadyReadStandardError()
{
    appendLog(QString(plotProcess->readAllStandardError()).replace("\r\n", "\n").split("\n"));
}
