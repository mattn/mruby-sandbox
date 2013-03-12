#include <mruby.h>
#include <mruby/string.h>
#include <mruby/compile.h>
#include <mruby/data.h>
#include <mruby/class.h>
#include <mruby/proc.h>
#include <mruby/variable.h>
#include <string.h>
#ifndef _MSC_VER
#include <strings.h>
#endif
#include <ctype.h>
#include <pthread.h>
#include <stdio.h>

typedef struct {
  mrb_state* mrb;
  mrbc_context *cxt;
} mrb_sandbox_context;

static void
mrb_sandbox_context_free(mrb_state *mrb, void *p) {
  mrb_sandbox_context* sc = (mrb_sandbox_context*) p;
  if (sc->cxt) mrbc_context_free(sc->mrb, sc->cxt);
  if (sc->mrb) mrb_close(sc->mrb);
  free(p);
}

static struct mrb_data_type mrb_sandbox_context_type = {
  "mrb_sandbox_context", mrb_sandbox_context_free,
};

static mrb_value
mrb_sandbox_init(mrb_state* mrb, mrb_value self) {
  mrb_sandbox_context* sc = (mrb_sandbox_context*) malloc(sizeof(mrb_sandbox_context));
  sc->mrb = mrb_open();
  sc->cxt = mrbc_context_new(sc->mrb);
  DATA_TYPE(self) = &mrb_sandbox_context_type;
  DATA_PTR(self) = sc;
  return self;
}

static mrb_value
mrb_sandbox_eval(mrb_state* mrb, mrb_value self) {
  mrb_sandbox_context* sc;
  struct mrb_parser_state *parser;
  int n;
  char* code;
  mrb_value result;
  mrb_value obj;
  mrb_get_args(mrb, "z", &code);

  sc = DATA_PTR(self);
  parser = mrb_parser_new(sc->mrb);
  parser->s = code;
  parser->send = code + strlen(code);
  parser->lineno = 1;
  mrb_parser_parse(parser, sc->cxt);
  if (0 < parser->nerr) {
	  mrb_raisef(mrb, E_RUNTIME_ERROR, "line %d: %s\n", parser->error_buffer[0].lineno, parser->error_buffer[0].message);
  }
	n = mrb_generate_code(sc->mrb, parser);
  mrb_parser_free(parser);
	result = mrb_run(sc->mrb,
    mrb_proc_new(sc->mrb, sc->mrb->irep[n]),
    mrb_top_self(sc->mrb));
	if (mrb->exc) {
    obj = mrb_funcall(sc->mrb, mrb_obj_value(sc->mrb->exc), "inspect", 0);
	  sc->mrb->exc = 0;
    mrb_raise(mrb, E_RUNTIME_ERROR, RSTRING_PTR(obj));
	}
  obj = mrb_funcall(sc->mrb, result, "inspect", 0);
  return mrb_str_new(mrb, RSTRING_PTR(obj), RSTRING_LEN(obj));
}

void
mrb_mruby_sandbox_gem_init(mrb_state* mrb) {
  struct RClass* _class_sandbox = mrb_define_class(mrb, "Sandbox", mrb->object_class);
  MRB_SET_INSTANCE_TT(_class_sandbox, MRB_TT_DATA);
  mrb_define_method(mrb, _class_sandbox, "initialize", mrb_sandbox_init, ARGS_NONE());
  mrb_define_method(mrb, _class_sandbox, "eval", mrb_sandbox_eval, ARGS_REQ(1));
}

void
mrb_mruby_sandbox_gem_final(mrb_state* mrb) {
}

/* vim:set et ts=2 sts=2 sw=2 tw=0: */
