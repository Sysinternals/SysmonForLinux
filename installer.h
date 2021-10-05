/*
    SysmonForLinux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

//====================================================================
//
// installer.h
//
// Functions that install Sysmon For Linux
//
//====================================================================

#include <stdbool.h>

bool installFiles(bool force);
bool copyConfigFile(const char *configFile);
bool createEmptyConfigFile();
bool writeArgv(int argc, char *argv[]);
bool readArgv(int *argc, char ***argv, char **configFile);
char *GetCommandLine();
bool writeFieldSizes(char *fieldSizesStr);
char *readFieldSizes();
bool setRunState(unsigned int runState, bool running);
bool stopSysmonService();
bool startSysmonService();
bool sysmonSearch(int signal);
void killOtherSysmon(bool force);
bool sysmonIsRunning();
void signalConfigChange();
bool displayConfig();
void uninstall();

