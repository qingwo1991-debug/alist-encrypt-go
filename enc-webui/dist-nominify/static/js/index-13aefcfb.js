import { _ as _export_sfc, d as defineComponent, e as useBasicStore, f as useElement, r as reactive, u as useRoute, w as watch, g as ref, a as useRouter, h as resolveComponent, i as openBlock, j as createElementBlock, c as createVNode, k as withCtx, l as createBaseVNode, t as toDisplayString, m as unref, n as createBlock, p as withKeys, q as withModifiers, b as createTextVNode, s as nextTick, v as __unplugin_components_0, x as pushScopeId, y as popScopeId, z as loginReq, A as elMessage } from "./index-1a909033.js";
const index_vue_vue_type_style_index_0_scoped_49b9eb85_lang = "";
const index_vue_vue_type_style_index_1_lang = "";
const _withScopeId = (n) => (pushScopeId("data-v-49b9eb85"), n = n(), popScopeId(), n);
const _hoisted_1 = { class: "login-container columnCC" };
const _hoisted_2 = { class: "title-container" };
const _hoisted_3 = { class: "title text-center" };
const _hoisted_4 = { class: "rowSC" };
const _hoisted_5 = { class: "svg-container" };
const _hoisted_6 = /* @__PURE__ */ _withScopeId(() => /* @__PURE__ */ createBaseVNode("div", { class: "show-pwd" }, null, -1));
const _hoisted_7 = { class: "rowSC flex-1" };
const _hoisted_8 = { class: "svg-container" };
const _hoisted_9 = { class: "tip-message" };
const __default__ = defineComponent({});
const _sfc_main = /* @__PURE__ */ Object.assign(__default__, {
  __name: "index",
  setup(__props) {
    const { settings } = useBasicStore();
    const formRules = useElement().formRules;
    const subForm = reactive({
      username: "admin",
      password: ""
    });
    const state = reactive({
      otherQuery: {},
      redirect: void 0
    });
    const route = useRoute();
    const getOtherQuery = (query) => {
      return Object.keys(query).reduce((acc, cur) => {
        if (cur !== "redirect") {
          acc[cur] = query[cur];
        }
        return acc;
      }, {});
    };
    watch(
      () => route.query,
      (query) => {
        if (query) {
          state.redirect = query.redirect;
          state.otherQuery = getOtherQuery(query);
        }
      },
      { immediate: true }
    );
    let subLoading = ref(false);
    let tipMessage = ref("");
    const refLoginForm = ref(null);
    const handleLogin = () => {
      var _a;
      (_a = refLoginForm.value) == null ? void 0 : _a.validate((valid) => {
        subLoading.value = true;
        if (valid)
          loginFunc();
      });
    };
    const router = useRouter();
    const basicStore = useBasicStore();
    const loginFunc = () => {
      loginReq(subForm).then(({ data }) => {
        elMessage("登录成功");
        basicStore.setToken(data == null ? void 0 : data.jwtToken);
        router.push("/");
      }).catch((err) => {
        tipMessage.value = err == null ? void 0 : err.msg;
      }).finally(() => {
        subLoading.value = false;
      });
    };
    const passwordType = ref("password");
    const refPassword = ref(null);
    const showPwd = () => {
      if (passwordType.value === "password") {
        passwordType.value = "";
      } else {
        passwordType.value = "password";
      }
      nextTick(() => {
        refPassword.value.focus();
      });
    };
    return (_ctx, _cache) => {
      const _component_svg_icon = __unplugin_components_0;
      const _component_el_input = resolveComponent("el-input");
      const _component_el_form_item = resolveComponent("el-form-item");
      const _component_el_button = resolveComponent("el-button");
      const _component_el_form = resolveComponent("el-form");
      return openBlock(), createElementBlock("div", _hoisted_1, [
        createVNode(_component_el_form, {
          ref_key: "refLoginForm",
          ref: refLoginForm,
          class: "login-form",
          model: subForm,
          rules: unref(formRules)
        }, {
          default: withCtx(() => [
            createBaseVNode("div", _hoisted_2, [
              createBaseVNode("h3", _hoisted_3, toDisplayString(unref(settings).title), 1)
            ]),
            createVNode(_component_el_form_item, {
              prop: "username",
              rules: unref(formRules).isNotNull("usename不能为空")
            }, {
              default: withCtx(() => [
                createBaseVNode("div", _hoisted_4, [
                  createBaseVNode("span", _hoisted_5, [
                    createVNode(_component_svg_icon, { "icon-class": "user" })
                  ]),
                  createVNode(_component_el_input, {
                    modelValue: subForm.username,
                    "onUpdate:modelValue": _cache[0] || (_cache[0] = ($event) => subForm.username = $event),
                    placeholder: "用户名(admin)"
                  }, null, 8, ["modelValue"]),
                  _hoisted_6
                ])
              ]),
              _: 1
            }, 8, ["rules"]),
            createVNode(_component_el_form_item, {
              prop: "password",
              rules: unref(formRules).isNotNull("密码不能为空")
            }, {
              default: withCtx(() => [
                createBaseVNode("div", _hoisted_7, [
                  createBaseVNode("span", _hoisted_8, [
                    createVNode(_component_svg_icon, { "icon-class": "password" })
                  ]),
                  (openBlock(), createBlock(_component_el_input, {
                    key: passwordType.value,
                    ref_key: "refPassword",
                    ref: refPassword,
                    modelValue: subForm.password,
                    "onUpdate:modelValue": _cache[1] || (_cache[1] = ($event) => subForm.password = $event),
                    type: passwordType.value,
                    name: "password",
                    placeholder: "password",
                    onKeyup: withKeys(handleLogin, ["enter"])
                  }, null, 8, ["modelValue", "type", "onKeyup"])),
                  createBaseVNode("span", {
                    class: "show-pwd",
                    onClick: showPwd
                  }, [
                    createVNode(_component_svg_icon, {
                      "icon-class": passwordType.value === "password" ? "eye" : "eye-open"
                    }, null, 8, ["icon-class"])
                  ])
                ])
              ]),
              _: 1
            }, 8, ["rules"]),
            createBaseVNode("div", _hoisted_9, toDisplayString(unref(tipMessage)), 1),
            createVNode(_component_el_button, {
              loading: unref(subLoading),
              type: "primary",
              class: "login-btn",
              size: "default",
              onClick: withModifiers(handleLogin, ["prevent"])
            }, {
              default: withCtx(() => [
                createTextVNode(" Login ")
              ]),
              _: 1
            }, 8, ["loading", "onClick"])
          ]),
          _: 1
        }, 8, ["model", "rules"])
      ]);
    };
  }
});
const index = /* @__PURE__ */ _export_sfc(_sfc_main, [["__scopeId", "data-v-49b9eb85"]]);
export {
  index as default
};
