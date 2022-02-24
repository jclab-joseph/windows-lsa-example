#include <windows.h>

#include <plog/Log.h>
#include <plog/Initializers/RollingFileInitializer.h>

static void logInit() {
  plog::init(plog::debug, "c:\\lsa_example.txt");
}

extern "C" BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved
) {
  UNREFERENCED_PARAMETER(hModule);
  UNREFERENCED_PARAMETER(lpReserved);

  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
      logInit();
      PLOG(plog::info) << "start";
      break;
    case DLL_THREAD_ATTACH:
      break;
    case DLL_THREAD_DETACH:
      break;
    case DLL_PROCESS_DETACH:
      break;
  }

  return TRUE;
}
