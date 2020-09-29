(/System/Library/Frameworks/Python.framework/Versions/2.7/Resources/Python.app/Contents/MacOS/Python -x "$0" >/dev/null 2>&1 &); exit
# coding:utf-8
# pylint: disable=too-many-statements, line-too-long, W0703, C0103

import base64
import os
import plistlib
import pty
import re
import subprocess

from AppKit import NSApp
from AppKit import NSAppleScript
from AppKit import NSApplication
from AppKit import NSApplicationActivationPolicyProhibited
from AppKit import NSBackingStoreBuffered
from AppKit import NSBezelBorder
from AppKit import NSClosableWindowMask
from AppKit import NSColor
from AppKit import NSData
from AppKit import NSFont
from AppKit import NSForegroundColorAttributeName
from AppKit import NSImage
from AppKit import NSMakeRange
from AppKit import NSMakeRect
from AppKit import NSMaxY
from AppKit import NSMenu
from AppKit import NSMenuItem
from AppKit import NSMutableAttributedString
from AppKit import NSObject
from AppKit import NSScrollView
from AppKit import NSStatusBar
from AppKit import NSTextView
from AppKit import NSTitledWindowMask
from AppKit import NSUserNotification
from AppKit import NSUserNotificationCenter
from AppKit import NSVariableStatusItemLength
from AppKit import NSViewHeightSizable
from AppKit import NSViewWidthSizable
from AppKit import NSWindow
from AppKit import NSWorkspace
from AppKit import NSWorkspaceWillPowerOffNotification
from PyObjCTools import AppHelper


CONSOLE_EXECUTABLE = "liner"
CONSOLE_TITLE = "liner"
CONSOLE_FONT = NSFont.fontWithName_size_("Monaco", 12.0)
ICON_DATA = """
iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAQAAAAAYLlVAAAABGdBTUEAAYagMeiWXwAAAAJiS0dE
AP+Hj8y/AAAACXBIWXMAAABIAAAASABGyWs+AAACh0lEQVRo3u2YQU8TQRTHf22hAUOTAsaqqNVy
kQuXCdGTB2+NJ2NQ4xcw8QIXIx68ePAoMRyM0QQSLhxMOBgCHIz6AZaAXmoVoiiIJIXSlNh2264X
2EyNXWfbZY1x/qfZN7Mzv31vdvLegNb/rkD9LgEhOgnVHVCljEkRE4yGAVoce2NM0kO1LoDJLhlW
SYlFUmxhuQdxBmill7jCLBZ50szzXLyl4g7COQRx3igB7GuDKcZYcROSoGufOekow0yTJCD+EgBA
P+PcUEdoURwHOSbYlkIWoo0ujnOakxyqGRnjIVlmhFIg1AF2GOWTPKWAAGG66SPJZc5IcEd4QIpl
lWmbCIGBYRlFY52X3CbJUwpSZz+3CKqEwYM9YGBYpBnifg3CVfoO2AO1EBQYZVwynSAJf/aBZ3+B
AQUesSKZLtLmmwf29J4Z6eksMV8BDIBXmLbhMD1+ewA+kLXb7T57AIAsObsdosN/gBIlux1QOea8
BghJCUyVov8AHZLby9J+8A3gFJ12O883XwEEwDnabcMaX/32QBeXpKcFMj4CCIArDNgGk9m66az3
AAJggDu02qYlXqvkhp4A7C3/mF7p+5/xXeVd9YzIafEog4yQkMxzTKnlxg0DCIAgEeJcYJDzhKXO
FPfYUZtHHSDCTTJiP+8LEibKMRIk6P4lkKsMs6RaG6gDRBlRGpdmiHn10sTbc6DMLNeZc1MZNb0J
bVVJ8YRJtt3Vyl4AVNlikWle8MV9oa4OUGYD0y4+LCqUyLHJMu9Y4CO7jd0SqANsco3P0p6pUOYH
heauJ9wAVFhnrZmlfi/vq2MNoAE0gAbQABpAA2gAl3LOiDLcJYIFBMirFNtaWlr/oH4Cs/ienoDW
K/QAAAAldEVYdGRhdGU6Y3JlYXRlADIwMTktMTEtMDRUMDA6MDc6NDArMDg6MDARhNf6AAAAJXRF
WHRkYXRlOm1vZGlmeQAyMDE3LTAyLTAzVDE4OjI0OjA2KzA4OjAwA25dRQAAAABJRU5ErkJggg==
"""
PROXY_MENU = [
    '<None>',
    'http://localhost:8087/china.pac',
    'localhost:8087',
]


def get_network_location():
    """get network location"""
    ps = plistlib.readPlistFromString(os.popen('system_profiler SPNetworkDataType -xml').read())
    network = next(x['_name'] for x in ps[0]['_items'] if x['IPv4'].get('Addresses'))
    return network


def get_current_proxy():
    """get current proxy string"""
    text = os.popen('scutil --proxy').read()
    info = dict(re.findall(r'(?m)^\s+([A-Z]\w+)\s+:\s+(\S+)', text))
    if info.get('HTTPEnable') == '1':
        return '%s:%s' % (info['HTTPProxy'], info['HTTPPort'])
    if info.get('ProxyAutoConfigEnable') == '1':
        return info['ProxyAutoConfigURLString']
    return '<None>'


class Systray(NSObject):

    def applicationDidFinishLaunching_(self, _notification):
        """setup systray ui"""
        self.statusitem = NSStatusBar.systemStatusBar().statusItemWithLength_(NSVariableStatusItemLength)
        # Set initial image
        raw_data = base64.b64decode(''.join(ICON_DATA.strip().splitlines()))
        self.image = NSImage.alloc().initWithData_(NSData.dataWithBytes_length_(raw_data, len(raw_data)))
        self.image.setSize_((18, 18))
        self.image.setTemplate_(True)
        self.statusitem.setImage_(self.image)
        # Let it highlight upon clicking
        self.statusitem.setHighlightMode_(1)
        # Set a tooltip
        self.statusitem.setToolTip_(CONSOLE_TITLE)
        # Build a very simple menu
        self.menu = NSMenu.alloc().init()
        # Show Menu Item
        self.menu.addItemWithTitle_action_keyEquivalent_('Show', self.show_, '').setTarget_(self)
        # Hide Menu Item
        self.menu.addItemWithTitle_action_keyEquivalent_('Hide', self.hide2_, '').setTarget_(self)
        # Proxy Menu Item
        self.submenu = NSMenu.alloc().init()
        self.submenu.addItemWithTitle_action_keyEquivalent_(PROXY_MENU[0], self.setproxy0_, '').setTarget_(self)
        self.submenu.addItemWithTitle_action_keyEquivalent_(PROXY_MENU[1], self.setproxy1_, '').setTarget_(self)
        self.submenu.addItemWithTitle_action_keyEquivalent_(PROXY_MENU[2], self.setproxy2_, '').setTarget_(self)
        menuitem = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_('Set Proxy', None, '')
        menuitem.setTarget_(self)
        menuitem.setSubmenu_(self.submenu)
        self.menu.addItem_(menuitem)
        self.menu.addItemWithTitle_action_keyEquivalent_('Reload', self.reset_, '').setTarget_(self)
        self.menu.addItemWithTitle_action_keyEquivalent_('Quit', self.exit_, '').setTarget_(self)
        self.statusitem.setMenu_(self.menu)
        # Console window
        frame = NSMakeRect(0, 0, 640, 480)
        self.console_window = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(frame, NSClosableWindowMask | NSTitledWindowMask, NSBackingStoreBuffered, False)
        self.console_window.setTitle_(CONSOLE_TITLE)
        self.console_window.setDelegate_(self)
        # Console view inside a scrollview
        self.scroll_view = NSScrollView.alloc().initWithFrame_(frame)
        self.scroll_view.setBorderType_(NSBezelBorder)
        self.scroll_view.setHasVerticalScroller_(True)
        self.scroll_view.setHasHorizontalScroller_(False)
        self.scroll_view.setAutoresizingMask_(NSViewWidthSizable | NSViewHeightSizable)
        self.console_view = NSTextView.alloc().initWithFrame_(frame)
        self.console_view.setBackgroundColor_(NSColor.blackColor())
        self.console_view.setRichText_(True)
        self.console_view.setVerticallyResizable_(True)
        self.console_view.setHorizontallyResizable_(True)
        self.console_view.setAutoresizingMask_(NSViewWidthSizable)
        self.scroll_view.setDocumentView_(self.console_view)
        self.console_window.contentView().addSubview_(self.scroll_view)
        # Update Proxy Menu
        AppHelper.callLater(1, self.updateproxystate_, None)
        # Hide dock icon
        NSApp.setActivationPolicy_(NSApplicationActivationPolicyProhibited)
        # Start Console Application
        self.master, self.slave = pty.openpty()
        self.pipe = subprocess.Popen('./' + CONSOLE_EXECUTABLE, shell=True, stdin=subprocess.PIPE, stdout=self.slave, stderr=self.slave, close_fds=True)
        self.pipe_fd = os.fdopen(self.master)
        self.performSelectorInBackground_withObject_('pollOutput', None)
        # Send Notification
        notification = NSUserNotification.alloc().init()
        notification.setTitle_('{} Started.'.format(CONSOLE_TITLE))
        notification.setSubtitle_('')
        notification.setInformativeText_('')
        notification.setSoundName_('NSUserNotificationDefaultSoundName')
        notification.setContentImage_(self.image)
        usernotifycenter = NSUserNotificationCenter.defaultUserNotificationCenter()
        usernotifycenter.removeAllDeliveredNotifications()
        usernotifycenter.setDelegate_(self)
        usernotifycenter.scheduleNotification_(notification)
        nc = NSWorkspace.sharedWorkspace().notificationCenter()
        nc.addObserver_selector_name_object_(self, 'exit:', NSWorkspaceWillPowerOffNotification, None)

    def windowWillClose_(self, _notification):
        """cleanup systray ui"""
        self.pipe.terminate()
        NSApp.terminate_(self)

    def userNotificationCenter_didActivateNotification_(self, center, notification):
        NSUserNotificationCenter.defaultUserNotificationCenter().removeAllDeliveredNotifications()

    def pollOutput(self):
        """poll output"""
        while True:
            line = self.pipe_fd.readline()
            self.performSelectorOnMainThread_withObject_waitUntilDone_('refreshDisplay:', line, None)

    def refreshDisplay_(self, line):
        """stub for pollOutput"""
        if line.startswith('\x1b['):
            line = re.sub(r'\x1b\[\d+m', '', line)
        console_line = NSMutableAttributedString.alloc().initWithString_(line)
        console_line.addAttribute_value_range_(NSForegroundColorAttributeName, NSColor.whiteColor(), NSMakeRange(0,len(line)))
        self.console_view.textStorage().appendAttributedString_(console_line)
        self.console_view.textStorage().setFont_(CONSOLE_FONT)
        if NSMaxY(self.console_view.visibleRect()) >= NSMaxY(self.console_view.bounds()):
            length = len(self.console_view.textStorage().mutableString())
            self.console_view.scrollRangeToVisible_(NSMakeRange(length, 0))
        # self.console_view.textContainer().setWidthTracksTextView_(False)
        # self.console_view.textContainer().setContainerSize_((640, 480))

    def updateproxystate_(self, _notification):
        """add checkmark to submenu"""
        proxy_title = get_current_proxy()
        for title in PROXY_MENU:
            state = 1 if title == proxy_title else 0
            self.submenu.itemWithTitle_(title).setState_(state)

    def setproxy0_(self, notification):
        """reset proxy"""
        network = get_network_location()
        script = '''do shell script "%s" with administrator privileges''' % ' && '.join([
            'networksetup -setwebproxystate %s off' % network,
            'networksetup -setsecurewebproxystate %s off' % network,
            'networksetup -setautoproxystate %s off' % network,
        ])
        NSAppleScript.alloc().initWithSource_(script).executeAndReturnError_(None)
        self.updateproxystate_(notification)

    def setproxy1_(self, notification):
        """set autoproxy"""
        pac_url = PROXY_MENU[1]
        network = get_network_location()
        script = '''do shell script "%s" with administrator privileges''' % ' && '.join([
            'networksetup -setautoproxyurl %s %s' % (network, pac_url),
            'networksetup -setautoproxystate %s on' % network,
            'networksetup -setwebproxystate %s off' % network,
            'networksetup -setsecurewebproxystate %s off' % network,
        ])
        NSAppleScript.alloc().initWithSource_(script).executeAndReturnError_(None)
        self.updateproxystate_(notification)

    def setproxy2_(self, notification):
        """set web proxy"""
        host, port = PROXY_MENU[2].rsplit(':')
        network = get_network_location()
        script = '''do shell script "%s" with administrator privileges''' % ' && '.join([
            'networksetup -setwebproxy %s %s %s' % (network, host, port),
            'networksetup -setwebproxystate %s on' % network,
            'networksetup -setsecurewebproxy %s %s %s' % (network, host, port),
            'networksetup -setsecurewebproxystate %s on' % network,
            'networksetup -setautoproxystate %s off' % network,
        ])
        NSAppleScript.alloc().initWithSource_(script).executeAndReturnError_(None)
        self.updateproxystate_(notification)

    def show_(self, _notification):
        """show"""
        self.console_window.center()
        self.console_window.orderFrontRegardless()
        self.console_window.setIsVisible_(True)

    def hide2_(self, _notification):
        """hide"""
        self.console_window.setIsVisible_(False)
        #self.console_window.orderOut(None)

    def reset_(self, _notification):
        """reset"""
        self.show_(True)
        self.pipe.terminate()
        os.system('killall ' + CONSOLE_EXECUTABLE)
        self.console_view.setString_('')
        self.master, self.slave = pty.openpty()
        self.pipe = subprocess.Popen('./' + CONSOLE_EXECUTABLE, shell=True, stdin=subprocess.PIPE, stdout=self.slave, stderr=self.slave, close_fds=True)
        self.pipe_fd = os.fdopen(self.master)
        self.performSelectorInBackground_withObject_('pollOutput', None)

    def exit_(self, _notification):
        """exit"""
        self.pipe.terminate()
        NSApp.terminate_(self)


def main():
    """main function"""
    os.environ['ENV'] = 'production'
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    app = NSApplication.sharedApplication()
    app.setDelegate_(Systray.alloc().init())
    AppHelper.runEventLoop()


if __name__ == '__main__':
    main()
