package com.company.remoteaccess;

import javafx.application.Application;

/**
 * Plain {@code main()} entry point for unpackaged / IDE runs. Keeps the app
 * non-modular so packaging stays simple.
 */
public class Launcher {

    public static void main(String[] args) {
        try {
            Application.launch(MainApp.class, args);
        } catch (Throwable t) {
            System.err.println("FATAL: " + t);
            t.printStackTrace();
        }
    }
}