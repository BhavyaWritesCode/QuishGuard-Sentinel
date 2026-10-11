package com.quishguard.desktop.monitor;

import com.sun.jna.Native;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Psapi;
import com.sun.jna.platform.win32.User32;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.platform.win32.WinDef.HWND;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.ptr.IntByReference;

import java.awt.*;
import java.util.logging.Logger;

public class WindowMonitor {

    private static final Logger log = Logger.getLogger(WindowMonitor.class.getName());

    public record ActiveWindow(
            String appName,
            String exePath,
            String windowTitle,
            Rectangle bounds
    ) {}

    public ActiveWindow getActiveWindow() {
        try {
            HWND hwnd = User32.INSTANCE.GetForegroundWindow();
            if (hwnd == null) return null;

            // Get window title
            char[] titleBuf = new char[512];
            User32.INSTANCE.GetWindowText(hwnd, titleBuf, 512);
            String title = Native.toString(titleBuf);

            // Get process ID
            IntByReference pid = new IntByReference();
            User32.INSTANCE.GetWindowThreadProcessId(hwnd, pid);

            // Get executable path from PID
            HANDLE process = Kernel32.INSTANCE.OpenProcess(
                    0x0410, // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
                    false,
                    pid.getValue()
            );

            String exePath = "Unknown";
            String appName = "Unknown";

            if (process != null) {
                char[] pathBuf = new char[1024];
                Psapi.INSTANCE.GetModuleFileNameExW(process, null, pathBuf, 1024);
                exePath = Native.toString(pathBuf);
                appName = extractAppName(exePath);
                Kernel32.INSTANCE.CloseHandle(process);
            }

            // Get window bounds
            WinDef.RECT rect = new WinDef.RECT();
            User32.INSTANCE.GetWindowRect(hwnd, rect);
            Rectangle bounds = new Rectangle(
                    rect.left, rect.top,
                    rect.right  - rect.left,
                    rect.bottom - rect.top
            );

            return new ActiveWindow(appName, exePath, title, bounds);

        } catch (Exception e) {
            log.warning("Failed to get active window: " + e.getMessage());
            return null;
        }
    }

    private String extractAppName(String exePath) {
        if (exePath == null || exePath.isBlank()) return "Unknown";
        String fileName = exePath.substring(exePath.lastIndexOf('\\') + 1);
        if (fileName.toLowerCase().endsWith(".exe")) {
            fileName = fileName.substring(0, fileName.length() - 4);
        }
        return capitalize(fileName);
    }

    private String capitalize(String s) {
        if (s == null || s.isEmpty()) return s;
        return Character.toUpperCase(s.charAt(0)) + s.substring(1).toLowerCase();
    }
}