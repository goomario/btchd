// Copyright (c) 2017-2018 The Bitcoin Ore developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MINERCONSOLE_H
#define BITCOIN_QT_MINERCONSOLE_H

#include <qt/guiutil.h>

#include <QWidget>

class PlatformStyle;

namespace Ui {
    class MinerConsole;
}

/** Local Bitcoin Miner console. */
class MinerConsole : public QWidget
{
    Q_OBJECT

public:
    explicit MinerConsole(const PlatformStyle *platformStyle, QWidget *parent);
    ~MinerConsole();

private:
    void notifyMiningStatusChange(bool mining);

private Q_SLOTS:
    void on_plotfileList_itemSelectionChanged(int row);
    void on_addPlotFileButton_clicked();
    void on_removePlotFileButton_clicked();
    void on_switchMiningButton_clicked();

private:
    Ui::MinerConsole *ui;

    bool mining;
};

#endif // BITCOIN_QT_MINERCONSOLE_H
