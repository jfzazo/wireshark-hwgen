/* capture_file.cpp
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

#include "capture_file.h"

/*
 * @file Capture file class
 *
 * Wraps the capture_file struct, cfile global, and callbacks.
 */

#include "globals.h"
capture_file cfile;

#include "file.h"
#include "log.h"

#include "ui/capture.h"

#include <QFileInfo>

// To do:
// - Add getters and (if needed) setters:
//   - Full filename

QString CaptureFile::no_capture_file_ = QObject::tr("[no capture file]");

CaptureFile::CaptureFile(QObject *parent, capture_file *cap_file) :
    QObject(parent),
    cap_file_(cap_file),
    file_title_(no_capture_file_),
    file_state_(QString())
{
#ifdef HAVE_LIBPCAP
    capture_callback_add(captureCallback, (gpointer) this);
#endif
    cf_callback_add(captureFileCallback, (gpointer) this);
}

CaptureFile::~CaptureFile()
{
    cf_callback_remove(captureFileCallback, this);
}

bool CaptureFile::isValid() const
{
    if (cap_file_ && cap_file_->state != FILE_CLOSED) { // XXX FILE_READ_IN_PROGRESS as well?
        return true;
    }
    return false;
}

void CaptureFile::retapPackets()
{
    if (cap_file_) {
        cf_retap_packets(cap_file_);
    }
}

capture_file *CaptureFile::globalCapFile()
{
    return &cfile;
}

gpointer CaptureFile::window()
{
    if (cap_file_) return cap_file_->window;
    return NULL;
}

void CaptureFile::captureFileCallback(gint event, gpointer data, gpointer user_data)
{
    CaptureFile *capture_file = static_cast<CaptureFile *>(user_data);
    if (!capture_file) return;

    capture_file->captureFileEvent(event, data);
}

#ifdef HAVE_LIBPCAP
void CaptureFile::captureCallback(gint event, capture_session *cap_session, gpointer user_data)
{
    CaptureFile *capture_file = static_cast<CaptureFile *>(user_data);
    if (!capture_file) return;

    capture_file->captureEvent(event, cap_session);
}
#endif

void CaptureFile::captureFileEvent(int event, gpointer data)
{
    switch(event) {
    case(cf_cb_file_opened):
    {
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Opened");
        cap_file_ = (capture_file *) data;
        QFileInfo cfi(QString::fromUtf8(cap_file_->filename));
        file_title_ = cfi.baseName();
        emit captureFileOpened();
        break;
    }
    case(cf_cb_file_closing):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Closing");
        file_state_ = tr(" [closing]");
        emit captureFileClosing();
        break;
    case(cf_cb_file_closed):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Closed");
        file_state_ = tr(" [closed]");
        emit captureFileClosed();
        cap_file_ = NULL;
        file_title_ = no_capture_file_;
        file_state_ = QString();
        break;
    case(cf_cb_file_read_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Read started");
        emit captureFileReadStarted();
        break;
    case(cf_cb_file_read_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Read finished");
        emit captureFileReadFinished();
        break;
    case(cf_cb_file_reload_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Reload started");
        emit captureFileReadStarted();
        break;
    case(cf_cb_file_reload_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Reload finished");
        emit captureFileReadFinished();
        break;

    case(cf_cb_packet_selected):
    case(cf_cb_packet_unselected):
    case(cf_cb_field_unselected):
        // Signals and slots handled elsewhere.
        break;

//    case(cf_cb_file_save_started): // data = string
//        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Save started");
//        break;
//    case(cf_cb_file_save_finished):
//        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Save finished");
//        break;
//    case(cf_cb_file_save_failed):
//        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Save failed");
//        break;
    default:
        g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: main_cf_callback %d %p", event, data);
        g_warning("CaptureFile::captureFileCallback: event %u unknown", event);
        break;
    }
}

void CaptureFile::captureEvent(int event, capture_session *cap_session)
{
#ifndef HAVE_LIBPCAP
    Q_UNUSED(event)
    Q_UNUSED(cap_session)
#else
    switch(event) {
    case(capture_cb_capture_prepared):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture prepared");
        emit captureCapturePrepared(cap_session);
        cap_file_ = cap_session->cf;
        break;
    case(capture_cb_capture_update_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update started");
        emit captureCaptureUpdateStarted(cap_session);
        break;
    case(capture_cb_capture_update_continue):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update continue");
        emit captureCaptureUpdateContinue(cap_session);
        break;
    case(capture_cb_capture_update_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update finished");
        emit captureCaptureUpdateFinished(cap_session);
        break;
    case(capture_cb_capture_fixed_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture fixed started");
        emit captureCaptureFixedStarted(cap_session);
        break;
    case(capture_cb_capture_fixed_continue):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture fixed continue");
        break;
    case(capture_cb_capture_fixed_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture fixed finished");
        emit captureCaptureFixedFinished(cap_session);
        break;
    case(capture_cb_capture_stopping):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture stopping");
        /* Beware: this state won't be called, if the capture child
             * closes the capturing on it's own! */
        emit captureCaptureStopping(cap_session);
        break;
    case(capture_cb_capture_failed):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture failed");
        emit captureCaptureFailed(cap_session);
        break;
    default:
        g_warning("main_capture_callback: event %u unknown", event);
    }
#endif // HAVE_LIBPCAP
}

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
