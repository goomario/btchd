// Copyright (c) 2017-2018 The BitcoinHD Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_PLOTCONSOLE_H
#define BITCOIN_QT_PLOTCONSOLE_H

#include <qt/guiutil.h>

#include <memory>

#include <QProcess>
#include <QString>
#include <QWidget>

class PlatformStyle;

namespace Ui {
    class PlotConsole;
}

QT_BEGIN_NAMESPACE
class QStringList;
QT_END_NAMESPACE

/** Local BitcoinHD plot console. */
class PlotConsole : public QWidget
{
    Q_OBJECT

public:
    explicit PlotConsole(const PlatformStyle *platformStyle, QWidget *parent);
    ~PlotConsole();

private:
    void notifyPlotStatusChanged(bool plotting);
    void saveSettings();
    void appendLog(const QStringList &lines);
    void updatePlotInfo();
    bool isShowPassphrase();

public Q_SLOTS:
    void close();

private Q_SLOTS:
    void on_plotParamSpinBox_changed(int i);
    void on_passphraseEdit_changed();
    void on_togglePassphraseButton_clicked();
    void on_genPassphraseButton_clicked();
    void on_setPlotPathButton_clicked();
    void on_startPlotButton_clicked();

    // process output
    void onPlotStarted();
    void onPlotFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onPlotReadyReadStandardOutput();
    void onPlotReadyReadStandardError();

private:
    Ui::PlotConsole *ui;
    const PlatformStyle *platformStyle;

    QString passphrase;

    std::unique_ptr<QProcess> plotProcess;
};

#endif // BITCOIN_QT_PLOTCONSOLE_H