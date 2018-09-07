// Copyright (c) 2017-2018 The BitcoinHD Core developers
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
class QStringList;
class QTemporaryFile;
class QTimer;
QT_END_NAMESPACE

/** Local BitcoinHD Miner console. */
class MinerConsole : public QWidget
{
    Q_OBJECT

public:
    explicit MinerConsole(const PlatformStyle *platformStyle, QWidget *parent);
    ~MinerConsole();

private:
    void notifyMiningStatusChanged(bool mining);
    void saveSettings();
    void savePlotfiles();
    void appendLog(const QStringList &lines);
    bool isShowPassphrase();

public Q_SLOTS:
    void close();

private Q_SLOTS:
    void on_passphraseEdit_changed();
    void on_togglePassphraseButton_clicked();
    void on_plotfileList_itemSelectionChanged();
    void on_addPlotFileButton_clicked();
    void on_removePlotFileButton_clicked();
    void on_switchMiningButton_clicked();

    // process output
    void onMiningStarted();
    void onMiningFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onMiningReadyReadStandardOutput();
    void onMiningReadyReadStandardError();

    // forge progress
    void onDeadlineChanged(int32_t nHeight, uint64_t nNonce, uint64_t nNewDeadline);
    void onCheckDeadlineTimeout();

Q_SIGNALS:
    void deadlineChanged(int32_t nHeight, uint64_t nNonce, uint64_t nNewDeadline);

private:
    Ui::MinerConsole *ui;
    const PlatformStyle *platformStyle;

    QString passphrase;

    std::unique_ptr<QTemporaryFile> minerConfigFile;
    std::unique_ptr<QProcess> minerProcess;

    QTimer *checkForgeTimer;
};

#endif // BITCOIN_QT_MINERCONSOLE_H
