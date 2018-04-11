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
#include <util.h>

#include <QDesktopWidget>
#include <QFile>
#include <QFileDialog>
#include <QMessageBox>
#include <QSettings>
#include <QStringList>
#include <QTemporaryFile>

#include <qt/plotconsole.moc>

namespace {
 
const char xplotterRelativePath[] = "tools/xplotter";
}

PlotConsole::PlotConsole(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PlotConsole)
{
    ui->setupUi(this);
    connect(this, SIGNAL(close()), this, SLOT(onClose()));

    QSettings settings;
    if (!restoreGeometry(settings.value("PlotConsoleWindowGeometry").toByteArray())) {
        // Restore failed (perhaps missing setting), center the window
        move(QApplication::desktop()->availableGeometry().center() - frameGeometry().center());
    }

    plotProcess = std::unique_ptr<QProcess>(new QProcess());
    connect(plotProcess.get(), SIGNAL(started()), this, SLOT(onPlotStarted()));
    connect(plotProcess.get(), SIGNAL(finished(int, QProcess::ExitStatus)), this, SLOT(onPlotFinished(int, QProcess::ExitStatus)));
    connect(plotProcess.get(), SIGNAL(readyReadStandardOutput()), this, SLOT(onPlotReadyReadStandardOutput()));
    connect(plotProcess.get(), SIGNAL(readyReadStandardError()), this, SLOT(onPlotReadyReadStandardError()));
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
}

void PlotConsole::close()
{
    QWidget::close();

    if (plotProcess->state() != QProcess::NotRunning) {
        plotProcess->kill();
    }
}

void PlotConsole::onPlotStarted()
{
}

void PlotConsole::onPlotFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
}

void PlotConsole::onPlotReadyReadStandardOutput()
{
}

void PlotConsole::onPlotReadyReadStandardError()
{
}
