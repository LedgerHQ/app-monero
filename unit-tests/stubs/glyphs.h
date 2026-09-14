#pragma once

/* Empty, and required.
 *
 * The device build generates glyphs.h from glyphs/. Here it only has to exist:
 * the SDK's ux_nbgl.h includes it, and every app source reaches that through
 * os.h. Even a test that touches no UI fails to compile without this file.
 *
 * No icon declarations are needed while CMakeLists.txt keeps the UI sources out
 * of the coverage lib. If a suite ever compiles one, declare the icons it uses.
 */
