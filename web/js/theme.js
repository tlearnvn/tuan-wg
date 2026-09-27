/* Tuấn WireGuard - áp dụng giao diện sáng/tối trước khi vẽ trang (tránh nháy màn hình) */
(function () {
  var t = null;
  try { t = localStorage.getItem('twg-theme'); } catch (e) { /* bỏ qua */ }
  if (t !== 'light' && t !== 'dark') {
    t = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  document.documentElement.setAttribute('data-theme', t);
})();
