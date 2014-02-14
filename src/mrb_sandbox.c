#include <mruby.h>
#include <mruby/string.h>
#include <mruby/compile.h>
#include "mruby/irep.h"
#include <mruby/data.h>
#include <mruby/class.h>
#include <mruby/proc.h>
#include <mruby/variable.h>
#include <string.h>
#ifndef _MSC_VER
#include <strings.h>
#endif
#include <ctype.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

extern void mrb_init_heap(mrb_state*);
extern void mrb_init_symtbl(mrb_state*);
extern void mrb_init_class(mrb_state*);
extern void mrb_init_object(mrb_state*);
extern void mrb_init_kernel(mrb_state*);
extern void mrb_init_comparable(mrb_state*);
extern void mrb_init_enumerable(mrb_state*);
extern void mrb_init_symbol(mrb_state*);
extern void mrb_init_exception(mrb_state*);
extern void mrb_init_proc(mrb_state*);
extern void mrb_init_string(mrb_state*);
extern void mrb_init_array(mrb_state*);
extern void mrb_init_hash(mrb_state*);
extern void mrb_init_numeric(mrb_state*);
extern void mrb_init_range(mrb_state*);
extern void mrb_init_gc(mrb_state*);
extern void mrb_init_mrblib(mrb_state*);

#define GEM_EXTERN(x) \
extern void mrb_mruby_ ## x ## _gem_init(mrb_state*); \
extern void mrb_mruby_ ## x ## _gem_final(mrb_state*); \
extern const uint8_t gem_mrblib_irep_mruby_ ## x[];
#define GEM_INIT(x, y) \
mrb_mruby_ ## x ## _gem_init(y);
#define GEM_INIT_IREP(x, y) \
mrb_load_irep(y, gem_mrblib_irep_mruby_ ## x);
#define GEM_FINAL(x, y) \
mrb_mruby_ ## x ## _gem_final(y);

GEM_EXTERN(sprintf);
GEM_EXTERN(math);
GEM_EXTERN(time);
GEM_EXTERN(struct);
GEM_EXTERN(enum_ext);
GEM_EXTERN(string_ext);
GEM_EXTERN(numeric_ext);
GEM_EXTERN(range_ext);
GEM_EXTERN(proc_ext);
GEM_EXTERN(symbol_ext);
GEM_EXTERN(random);
GEM_EXTERN(array_ext);
GEM_EXTERN(hash_ext);
GEM_EXTERN(fiber);
GEM_EXTERN(object_ext);
GEM_EXTERN(objectspace);
GEM_EXTERN(toplevel_ext);

mrb_value
mrb_yield_internal(mrb_state *mrb, mrb_value b, int argc, mrb_value *argv, mrb_value self, struct RClass *c);
#ifdef _WIN32
#include <windows.h>
#define SIGALRM 14
typedef void (*sighandler_t)(int);
struct {
  DWORD t;
  HANDLE h;
  sighandler_t f;
} alarm_context = {0};

void alarm_thread(void* arg) {
  if (WaitForSingleObject(GetCurrentThread(), alarm_context.t) == WAIT_TIMEOUT) {
    if (alarm_context.f) alarm_context.f(SIGALRM);
  }
}

void alarm(int sec) {
  alarm_context.t = sec * 1000;
  if (sec == 0) {
    alarm_context.f = NULL;
  } else {
    if (alarm_context.h != NULL) {
      alarm_context.f = NULL;
    }
	  alarm_context.h = (HANDLE) _beginthread(alarm_thread, 0, NULL);
  }
}

void _signal(int sig, sighandler_t t) {
  if (sig == SIGALRM) {
    alarm_context.f = t;
    if (t == SIG_IGN) alarm_context.f = NULL;
    if (alarm_context.h != NULL) {
      TerminateThread(alarm_context.h, 0);
      alarm_context.h = NULL;
    }
  } else {
    signal(sig, t);
  }
}
#define signal(x, y) _signal(x, y)
#endif

typedef struct {
  mrb_state* mrb;
  mrbc_context *cxt;
  int timeout;
} mrb_sandbox_context;

static void
mrb_sandbox_context_free(mrb_state *mrb, void *p) {
  mrb_sandbox_context* sc = (mrb_sandbox_context*) p;
  if (sc->cxt) mrbc_context_free(sc->mrb, sc->cxt);
  if (sc->mrb) {
    GEM_FINAL(sprintf, sc->mrb);
    GEM_FINAL(math, sc->mrb);
    GEM_FINAL(time, sc->mrb);
    GEM_FINAL(struct, sc->mrb);
    GEM_FINAL(string_ext, sc->mrb);
    GEM_FINAL(numeric_ext, sc->mrb);
    GEM_FINAL(range_ext, sc->mrb);
    GEM_FINAL(proc_ext, sc->mrb);
    GEM_FINAL(random, sc->mrb);
    GEM_FINAL(array_ext, sc->mrb);
    mrb_close(sc->mrb);
  }
  free(p);
}

static struct mrb_data_type mrb_sandbox_context_type = {
  "mrb_sandbox_context", mrb_sandbox_context_free,
};

#define DONE mrb_gc_arena_restore(mrb, ai);

static void*
allocf(mrb_state *mrb, void *p, size_t size, void *ud)
{
  if (size == 0) {
    free(p);
    return NULL;
  }
  else {
    return realloc(p, size);
  }
}

static mrb_state*
my_mrb_open_allocf(mrb_allocf f, void *ud)
{
  static const mrb_state mrb_state_zero = { 0 };
  static const struct mrb_context mrb_context_zero = { 0 };
  mrb_state *mrb = (mrb_state *)(f)(NULL, NULL, sizeof(mrb_state), ud);
  if (mrb == NULL) return NULL;

  *mrb = mrb_state_zero;
  mrb->ud = ud;
  mrb->allocf = f;
  mrb->current_white_part = MRB_GC_WHITE_A;

#ifndef MRB_GC_FIXED_ARENA
  mrb->arena = (struct RBasic**)mrb_malloc(mrb, sizeof(struct RBasic*)*MRB_GC_ARENA_SIZE);
  mrb->arena_capa = MRB_GC_ARENA_SIZE;
#endif

  mrb_init_heap(mrb);
  mrb->c = (struct mrb_context*)mrb_malloc(mrb, sizeof(struct mrb_context));
  *mrb->c = mrb_context_zero;
  mrb->root_c = mrb->c;

  int ai = mrb_gc_arena_save(mrb);
  mrb_init_symtbl(mrb); DONE;

  mrb_init_class(mrb); DONE;
  mrb_init_object(mrb); DONE;
  mrb_init_kernel(mrb); DONE;
  mrb_init_comparable(mrb); DONE;
  mrb_init_enumerable(mrb); DONE;

  mrb_init_symbol(mrb); DONE;
  mrb_init_exception(mrb); DONE;
  mrb_init_proc(mrb); DONE;
  mrb_init_string(mrb); DONE;
  mrb_init_array(mrb); DONE;
  mrb_init_hash(mrb); DONE;
  mrb_init_numeric(mrb); DONE;
  mrb_init_range(mrb); DONE;
  mrb_init_gc(mrb); DONE;
  mrb_init_mrblib(mrb); DONE;

  GEM_INIT(sprintf, mrb); DONE;

  GEM_INIT(math, mrb); DONE;

  GEM_INIT(time, mrb); DONE;

  GEM_INIT(struct, mrb); DONE;
  GEM_INIT_IREP(struct, mrb); DONE;

  GEM_INIT_IREP(enum_ext, mrb); DONE;

  GEM_INIT(string_ext, mrb); DONE;
  GEM_INIT_IREP(string_ext, mrb); DONE;

  GEM_INIT(numeric_ext, mrb); DONE;

  GEM_INIT(array_ext, mrb); DONE;
  GEM_INIT_IREP(array_ext, mrb); DONE;

  GEM_INIT(hash_ext, mrb); DONE;
  GEM_INIT_IREP(hash_ext, mrb); DONE;

  GEM_INIT(range_ext, mrb); DONE;

  GEM_INIT(proc_ext, mrb); DONE;
  GEM_INIT_IREP(proc_ext, mrb); DONE;

  GEM_INIT(symbol_ext, mrb); DONE;
  GEM_INIT_IREP(symbol_ext, mrb); DONE;

  GEM_INIT(random, mrb); DONE;

  GEM_INIT(object_ext, mrb); DONE;

  GEM_INIT(objectspace, mrb); DONE;

  GEM_INIT(fiber, mrb); DONE;

  GEM_INIT_IREP(toplevel_ext, mrb); DONE;

  return mrb;
}

static mrb_value
mrb_sandbox_init(mrb_state* mrb, mrb_value self) {
  mrb_sandbox_context* sc = (mrb_sandbox_context*) malloc(sizeof(mrb_sandbox_context));

  sc->mrb = my_mrb_open_allocf(allocf, NULL);
  sc->cxt = mrbc_context_new(sc->mrb);
  sc->cxt->capture_errors = 1;
  sc->timeout = 3;
  DATA_TYPE(self) = &mrb_sandbox_context_type;
  DATA_PTR(self) = sc;
  return self;
}

static mrb_state* last_mrb = NULL;
static struct RObject* timeout_error = NULL;

static void
f_timeout(int sig) {
  last_mrb->exc = timeout_error;
}

static mrb_value
mrb_sandbox_eval(mrb_state* mrb, mrb_value self) {
  mrb_sandbox_context* sc;
  struct mrb_parser_state *parser;
  char* code;
  mrb_value result, ret;
  mrb_value obj;
  mrb_get_args(mrb, "z", &code);

  sc = DATA_PTR(self);
  parser = mrb_parser_new(sc->mrb);
  parser->s = code;
  parser->send = code + strlen(code);
  parser->lineno = 1;
  mrb_parser_parse(parser, sc->cxt);
  if (0 < parser->nerr) {
    mrb_parser_free(parser);
    return mrb_nil_value();
  }
  struct RProc *proc = mrb_generate_code(sc->mrb, parser);
  mrb_parser_free(parser);

  last_mrb = sc->mrb;
  timeout_error = (struct RObject*) mrb_object(mrb_funcall(
    sc->mrb,
    mrb_obj_value(mrb_class_get(sc->mrb, "RuntimeError")),
      "new", 1, mrb_str_new_cstr(sc->mrb, "Timeout")));
  signal(SIGALRM, f_timeout);
  alarm(sc->timeout);
  int ai = mrb_gc_arena_save(mrb);
  int ai_sc = mrb_gc_arena_save(sc->mrb);
  result = mrb_run(sc->mrb, proc, mrb_top_self(sc->mrb));
  signal(SIGALRM, SIG_IGN);
  alarm(0);
  if (sc->mrb->exc)
    obj = mrb_funcall(sc->mrb, mrb_obj_value(sc->mrb->exc), "inspect", 0);
  else
    obj = mrb_funcall(sc->mrb, result, "to_s", 0);
  ret = mrb_str_new(mrb, RSTRING_PTR(obj), RSTRING_LEN(obj));
  mrb_garbage_collect(sc->mrb);
  mrb_gc_arena_restore(mrb, ai);
  mrb_gc_arena_restore(sc->mrb, ai_sc);
  sc->mrb->exc = 0;
  return ret;
}

static mrb_value
mrb_sandbox_timeout_get(mrb_state *mrb, mrb_value self) {
  return mrb_fixnum_value(((mrb_sandbox_context*) DATA_PTR(self))->timeout);
}

static mrb_value
mrb_sandbox_timeout_set(mrb_state *mrb, mrb_value self) {
  mrb_get_args(mrb, "i", &(((mrb_sandbox_context*) DATA_PTR(self))->timeout));
  return mrb_fixnum_value(((mrb_sandbox_context*) DATA_PTR(self))->timeout);
}

void
mrb_mruby_sandbox_gem_init(mrb_state* mrb) {
  struct RClass* _class_sandbox = mrb_define_class(mrb, "Sandbox", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_sandbox, MRB_TT_DATA);
  mrb_define_method(mrb, _class_sandbox, "initialize", mrb_sandbox_init, ARGS_NONE());
  mrb_define_method(mrb, _class_sandbox, "eval", mrb_sandbox_eval, ARGS_REQ(1));
  mrb_define_method(mrb, _class_sandbox, "timeout", mrb_sandbox_timeout_get, ARGS_NONE());
  mrb_define_method(mrb, _class_sandbox, "timeout=", mrb_sandbox_timeout_set, ARGS_REQ(1));
}

void
mrb_mruby_sandbox_gem_final(mrb_state* mrb) {
}

/* vim:set et ts=2 sts=2 sw=2 tw=0: */
