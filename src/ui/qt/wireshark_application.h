/* wireshark_application.h
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

#ifndef WIRESHARK_APPLICATION_H
#define WIRESHARK_APPLICATION_H

#include <config.h>

#include <glib.h>

#include "epan/prefs.h"

#include "capture_opts.h"
#include <capchild/capture_session.h>
#include "file.h"
#include "register.h"

#include "ui/help_url.h"

#include <QApplication>
#include <QFileInfo>
#include <QFont>
#include <QIcon>
#include <QList>
#include <QSocketNotifier>
#include <QThread>
#include <QTimer>
#include <QTranslator>


// Recent items:
// - Read from prefs
// - Add from open file
// - Check current list
// - Signal updated item
// -
typedef struct _recent_item_status {
    QString filename;
    qint64 size;
    bool accessible;
    bool in_thread;
} recent_item_status;

class WiresharkApplication : public QApplication
{
    Q_OBJECT
public:
    explicit WiresharkApplication(int &argc,  char **argv);

    enum AppSignal {
        ColumnsChanged,
        FilterExpressionsChanged,
        PacketDissectionChanged,
        PreferencesChanged,
        StaticRecentFilesRead,
        FieldsChanged
    };

    void registerUpdate(register_action_e action, const char *message);
    void emitAppSignal(AppSignal signal);
    void emitStatCommandSignal(const QString &menu_path, const char *arg, void *userdata);
    void allSystemsGo();
    void refreshLocalInterfaces();
    e_prefs * readConfigurationFiles(char **gdp_path, char **dp_path);
    QList<recent_item_status *> recentItems() const;
    void addRecentItem(const QString &filename, qint64 size, bool accessible);
    QDir lastOpenDir();
    void setLastOpenDir(const char *dir_name);
    void setLastOpenDir(QString *dir_str);
    void helpTopicAction(topic_action_e action);
    const QFont monospaceFont() const { return mono_font_; }
    void setMonospaceFont(const char *font_string);
    int monospaceTextSize(const char *str);
    void setConfigurationProfile(const gchar *profile_name);
    bool isInitialized() { return initialized_; }
    const QIcon &normalIcon() const { return normal_icon_; }
    const QIcon &captureIcon() const { return capture_icon_; }
    const QString &windowTitleSeparator() const { return window_title_separator_; }
    const QString windowTitleString(QStringList title_parts);
    const QString windowTitleString(QString title_part) { return windowTitleString(QStringList() << title_part); }

    QTranslator translator;
    QTranslator translatorQt;
    void loadLanguage(const QString& language);

private:
    bool initialized_;
    QFont mono_font_;
    QTimer recent_timer_;
    QTimer addr_resolv_timer_;
    QTimer tap_update_timer_;
    QList<QString> pending_open_files_;
    QSocketNotifier *if_notifier_;
    QIcon normal_icon_;
    QIcon capture_icon_;
    static QString window_title_separator_;

protected:
    bool event(QEvent *event);

signals:
    void appInitialized();
    void localInterfaceListChanged();
    void openCaptureFile(QString &cf_path, QString &display_filter, unsigned int type);
    void recentFilesRead();
    void updateRecentItemStatus(const QString &filename, qint64 size, bool accessible);
    void splashUpdate(register_action_e action, const char *message);
    void configurationProfileChanged(const gchar *profile_name);

    void columnsChanged(); // XXX This recreates the packet list. We might want to rename it accordingly.
    void filterExpressionsChanged();
    void packetDissectionChanged();
    void preferencesChanged();
    void addressResolutionChanged();
    void fieldsChanged();

    void openStatCommandDialog(const QString &menu_path, const char *arg, void *userdata);

public slots:
    void clearRecentItems();
    void captureFileReadStarted();
    void updateTaps();

private slots:
    void cleanup();
    void ifChangeEventsAvailable();
    void itemStatusFinished(const QString filename = "", qint64 size = 0, bool accessible = false);
    void refreshRecentFiles(void);
    void refreshAddressResolution(void);
};

extern WiresharkApplication *wsApp;

/** Global compile time version string */
extern GString *comp_info_str;
/** Global runtime version string */
extern GString *runtime_info_str;

#endif // WIRESHARK_APPLICATION_H

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
