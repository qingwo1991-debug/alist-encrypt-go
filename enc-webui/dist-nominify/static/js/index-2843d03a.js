import { d as defineComponent, u as useRoute, a as useRouter, o as onBeforeMount, c as createVNode, b as createTextVNode } from "./index-1a909033.js";
const index = /* @__PURE__ */ defineComponent({
  setup() {
    const route = useRoute();
    const router = useRouter();
    onBeforeMount(() => {
      const {
        params,
        query
      } = route;
      const {
        path
      } = params;
      router.replace({
        path: `/${path}`,
        query
      });
    });
    return () => createVNode("div", null, [createTextVNode(" ")]);
  }
});
export {
  index as default
};
