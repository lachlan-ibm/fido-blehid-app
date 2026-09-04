/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.util;

import android.view.View;

import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

/**
 * Utility methods for applying system window insets (status bar, navigation bar,
 * display cutouts) to views so that UI elements are never hidden behind OS chrome
 * on edge-to-edge displays.
 *
 * <p>Usage pattern in every Activity:</p>
 * <pre>
 *   // 1. Before setContentView — let the window draw behind system bars:
 *   WindowCompat.setDecorFitsSystemWindows(getWindow(), false);
 *
 *   // 2. After setContentView — push toolbar content below the status bar:
 *   InsetsHelper.applyTopInsetToToolbar(findViewById(R.id.toolbar));
 *
 *   // 3. After setContentView — push bottom buttons above the nav bar:
 *   InsetsHelper.applyBottomInset(findViewById(R.id.myBottomContainer));
 * </pre>
 */
public final class InsetsHelper {

    private InsetsHelper() {}

    /**
     * Registers an {@link androidx.core.view.OnApplyWindowInsetsListener} on {@code toolbar}
     * that adds the system top inset (status bar + cutout) as top padding.
     *
     * <p>The toolbar height is left unchanged; the padding pushes content downward
     * inside the bar so the Back and Home buttons are always accessible.</p>
     *
     * @param toolbar the {@code Toolbar} or root view of {@code toolbar_with_back.xml}
     */
    public static void applyTopInsetToToolbar(View toolbar) {
        ViewCompat.setOnApplyWindowInsetsListener(toolbar, (v, windowInsets) -> {
            Insets insets = windowInsets.getInsets(
                    WindowInsetsCompat.Type.systemBars() |
                    WindowInsetsCompat.Type.displayCutout());
            v.setPadding(
                    v.getPaddingLeft(),
                    insets.top,
                    v.getPaddingRight(),
                    v.getPaddingBottom());
            return windowInsets;
        });
    }

    /**
     * Registers an {@link androidx.core.view.OnApplyWindowInsetsListener} on {@code view}
     * that adds the system bottom inset (navigation bar + cutout) to the view's
     * existing bottom padding.
     *
     * <p>The original padding values are captured once at call time so repeated inset
     * dispatches do not accumulate extra padding.</p>
     *
     * @param view the container whose bottom edge should clear the navigation bar
     */
    public static void applyBottomInset(View view) {
        final int origLeft   = view.getPaddingLeft();
        final int origTop    = view.getPaddingTop();
        final int origRight  = view.getPaddingRight();
        final int origBottom = view.getPaddingBottom();

        ViewCompat.setOnApplyWindowInsetsListener(view, (v, windowInsets) -> {
            Insets insets = windowInsets.getInsets(
                    WindowInsetsCompat.Type.systemBars() |
                    WindowInsetsCompat.Type.displayCutout());
            v.setPadding(
                    origLeft,
                    origTop,
                    origRight,
                    origBottom + insets.bottom);
            return windowInsets;
        });
    }
}
