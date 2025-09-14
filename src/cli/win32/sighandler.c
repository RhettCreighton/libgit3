/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "git3_util.h"
#include <windows.h>

#include "sighandler.h"

static void (*interrupt_handler)(void) = NULL;

static BOOL WINAPI interrupt_proxy(DWORD signal)
{
	GIT3_UNUSED(signal);
	interrupt_handler();
	return TRUE;
}

int cli_sighandler_set_interrupt(void (*handler)(void))
{
	BOOL result;

	if ((interrupt_handler = handler) != NULL)
		result = SetConsoleCtrlHandler(interrupt_proxy, FALSE);
	else
		result = SetConsoleCtrlHandler(NULL, FALSE);

	if (!result) {
		git3_error_set(GIT3_ERROR_OS, "could not set control control handler");
		return -1;
	}

	return 0;
}
