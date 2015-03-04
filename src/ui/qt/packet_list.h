/* packet_list.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef PACKET_LIST_H
#define PACKET_LIST_H

#include "byte_view_tab.h"
#include "packet_list_model.h"
#include "preferences_dialog.h"
#include "proto_tree.h"
#include "related_packet_delegate.h"

#include <QTreeView>
#include <QTreeWidget>
#include <QMenu>

class QAction;

class PacketList : public QTreeView
{
    Q_OBJECT
public:
    enum ColumnActions {
        caAlignLeft,
        caAlignCenter,
        caAlignRight,
        caColumnPreferences,
        caEditColumn,
        caResolveNames,
        caResizeToContents,
        caDisplayedColumns,
        caHideColumn,
        caRemoveColumn
    };
    explicit PacketList(QWidget *parent = 0);
    PacketListModel *packetListModel() const;
    void setProtoTree(ProtoTree *proto_tree);
    void setByteViewTab(ByteViewTab *byteViewTab);
    void freeze();
    void thaw();
    void clear();
    void writeRecent(FILE *rf);
    bool contextMenuActive();
    QString &getFilterFromRowAndColumn();
    QString packetComment();
    void setPacketComment(QString new_comment);
    QString allPacketComments();

protected:
    void showEvent (QShowEvent *event);
    void selectionChanged (const QItemSelection & selected, const QItemSelection & deselected);
    void contextMenuEvent(QContextMenuEvent *event);


private:
    PacketListModel *packet_list_model_;
    ProtoTree *proto_tree_;
    ByteViewTab *byte_view_tab_;
    capture_file *cap_file_;
    QMenu ctx_menu_;
    QAction *decode_as_;
    int ctx_column_;

    RelatedPacketDelegate related_packet_delegate_;
    QMenu header_ctx_menu_;
    QMap<ColumnActions, QAction*> header_actions_;
    QList<ColumnActions> checkable_actions_;
    int header_ctx_column_;
    QAction *show_hide_separator_;
    QList<QAction *>show_hide_actions_;

    void markFramesReady();
    void setFrameMark(gboolean set, frame_data *fdata);
    void setFrameIgnore(gboolean set, frame_data *fdata);
    void setFrameReftime(gboolean set, frame_data *fdata);
    void setColumnVisibility();
    void initHeaderContextMenu();

signals:
    void packetDissectionChanged();
    void packetSelectionChanged();
    void showPreferences(PreferencesDialog::PreferencesPane start_pane);
    void editColumn(int column);

public slots:
    void setCaptureFile(capture_file *cf);
    void setMonospaceFont(const QFont &mono_font);
    void goNextPacket();
    void goPreviousPacket();
    void goFirstPacket();
    void goLastPacket();
    void goToPacket(int packet);
    void markFrame();
    void markAllDisplayedFrames(bool set);
    void ignoreFrame();
    void ignoreAllDisplayedFrames(bool set);
    void setTimeReference();
    void unsetAllTimeReferences();
    void redrawVisiblePackets();

private slots:
    void addRelatedFrame(int related_frame);
    void showHeaderMenu(QPoint pos);
    void headerMenuTriggered();
    void columnVisibilityTriggered();
};

#endif // PACKET_LIST_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
