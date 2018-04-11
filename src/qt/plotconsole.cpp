// Copyright (c) 2017-2018 The Bitcoin Ore developers
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
#include <poc/poc.h>
#include <util.h>

#include <QDesktopWidget>
#include <QFile>
#include <QFileDialog>
#include <QMessageBox>
#include <QScrollBar>
#include <QSettings>
#include <QStorageInfo>
#include <QStringList>
#include <QTemporaryFile>

#include <qt/plotconsole.moc>

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
    ui(new Ui::PlotConsole)
{
    ui->setupUi(this);
    connect(ui->noncesSpinBox, SIGNAL(valueChanged(int)), this, SLOT(plotSpinBoxValueChanged(int)));

    QSettings settings;
    if (!restoreGeometry(settings.value("PlotConsoleWindowGeometry").toByteArray())) {
        // Restore failed (perhaps missing setting), center the window
        move(QApplication::desktop()->availableGeometry().center() - frameGeometry().center());
    }

    // Load config
    ui->passphraseLineEdit->setText(settings.value(passphraseSettingsKey, "").toString());
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

void PlotConsole::saveSettings()
{
    QSettings settings;
    settings.setValue(passphraseSettingsKey, ui->passphraseLineEdit->text());
    settings.setValue(startNonceSettingsKey, ui->startNonceSpinBox->value());
    settings.setValue(noncesSettingsKey, ui->noncesSpinBox->value());
    settings.setValue(threadNumberSettingsKey, ui->threadsSpinBox->value());
    settings.setValue(memoryGBSettingsKey, ui->memoryGBSpinBox->value());
    settings.setValue(folderSettingsKey, ui->plotfolderLineEdit->text());
}

void PlotConsole::appendLog(const QStringList &lines)
{
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

void PlotConsole::updatePlotInfo()
{
    QString info;

    // plot file size
    int64_t requireByteSize = ui->noncesSpinBox->value() * 256LL * 1024;
    info += tr("The plot file size %1GB.").arg(1.0f * requireByteSize / 1024 / 1024 / 1024, 5, 'f', 2);

    // validate space
    if (!ui->plotfolderLineEdit->text().isEmpty()) {
        int64_t availableByteSize = (int64_t)QStorageInfo(ui->plotfolderLineEdit->text()).bytesAvailable();
        info += "\n" + tr("The destination folder free size %1GB.").arg(1.0f * availableByteSize / 1024 / 1024 / 1024, 5, 'f', 2);
        if (availableByteSize < requireByteSize) {
            info += "\n" + tr("This folder free size not enough!") ;
        }
    }

    ui->plotinfoLabel->setText(info);
}

void PlotConsole::plotSpinBoxValueChanged(int)
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
        if (ui->passphraseLineEdit->text().isEmpty()) {
            QMessageBox::information(this, "Plot console", QString("Please input your passphare!"));
            return;
        }
        if (ui->plotfolderLineEdit->text().isEmpty()) {
            QMessageBox::information(this, "Plot console", QString("Please input plot folder!"));
            return;
        }

        ui->startPlotButton->setEnabled(false);

#ifdef WIN32
        const QString xplotterDir = QString::fromWCharArray((GetAppDir() / xplotterRelativePath).c_str());
        const QString xplotterFile = "XPlotter_sse.exe";
#else
        const QString xplotterDir = QString((GetAppDir() / xplotterRelativePath).c_str());
        const QString xplotterFile = "XPlotter_sse";
#endif
        const QStringList arguments = QStringList() 
            << "-id" << QString::number(poc::GetAccountIdByPassPhrase(ui->passphraseLineEdit->text().toStdString()))
            << "-sn" << QString::number(ui->startNonceSpinBox->value())
            << "-n" << QString::number(ui->noncesSpinBox->value())
            << "-t" << QString::number(ui->threadsSpinBox->value())
            << "-mem" << QString::number(ui->memoryGBSpinBox->value()) + "G"
            << "-path" << ui->plotfolderLineEdit->text();

        plotProcess->setWorkingDirectory(xplotterDir);
        plotProcess->start(xplotterDir + "/" + xplotterFile, arguments, QProcess::ReadOnly);
    } else {
        // Stop plot
        ui->startPlotButton->setEnabled(false);
        plotProcess->kill();
    }
}

void PlotConsole::onPlotStarted()
{
    saveSettings();

    ui->startPlotButton->setEnabled(true);
    ui->logPlainTextEdit->clear();
    appendLog(QStringList() << QString("Start plot") << "" << "");
}

void PlotConsole::onPlotFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    ui->startPlotButton->setEnabled(true);
    appendLog(QStringList() << QString("Stop plot (") + QString::number((int)exitStatus) + QString(")"));
}

void PlotConsole::onPlotReadyReadStandardOutput()
{
    appendLog(QString(plotProcess->readAllStandardOutput()).replace("\r\n", "\n").split("\n"));
}

void PlotConsole::onPlotReadyReadStandardError()
{
    appendLog(QString(plotProcess->readAllStandardError()).replace("\r\n", "\n").split("\n"));
}
