import { reactive } from "vue";

export const auth = reactive({
  checked: false,
  authenticated: false,
  username: "",
  role: "",
});

let toastId = 0;
export const toasts = reactive([]);

export function pushToast(message, kind = "error") {
  const id = ++toastId;
  toasts.push({ id, message, kind });
  setTimeout(() => {
    const idx = toasts.findIndex((t) => t.id === id);
    if (idx !== -1) toasts.splice(idx, 1);
  }, 5000);
}
