#ifdef INJECTDLL_EXPORTS
#define INJECTDLL_API __declspec(dllexport)
#else
#define INJECTDLL_API __declspec(dllimport)
#endif

extern "C" INJECTDLL_API int InjectHook();