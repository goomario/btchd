// Copyright (c) 2017-2018 The Bitcoin Ore developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MINERCONSOLE_H
#define BITCOIN_QT_MINERCONSOLE_H

#include <qt/guiutil.h>

#include <memory>

#include <QProcess>
#include <QString>
#include <QWidget>

class PlatformStyle;

namespace Ui {
    class MinerConsole;
}

QT_BEGIN_NAMESPACE
class QTemporaryFile;
QT_END_NAMESPACE

/** Local Bitcoin Miner console. */
class MinerConsole : public QWidget
{
    Q_OBJECT

public:
    explicit MinerConsole(const PlatformStyle *platformStyle, QWidget *parent);
    ~MinerConsole();

private:
    void notifyMiningStatusChanged(bool mining);
    void saveSettings();

private Q_SLOTS:
    void on_plotfileList_itemSelectionChanged(int row);
    void on_addPlotFileButton_clicked();
    void on_removePlotFileButton_clicked();
    void on_switchMiningButton_clicked();

    // process output
    void onMiningStarted();
    void onMiningFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onMiningReadyReadStandardOutput();
    void onMiningReadyReadStandardError();

private:
    Ui::MinerConsole *ui;

    std::shared_ptr<QTemporaryFile> minerConfigFile;
    std::shared_ptr<QProcess> minerProcess;
};

#endif // BITCOIN_QT_MINERCONSOLE_H
