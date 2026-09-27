/*
 * Tuấn WireGuard - gọi REST API
 * Tác giả: Tuandethuong
 */
export class ApiError extends Error {
  constructor(msg, status) { super(msg); this.status = status; }
}

let onUnauthorized = null;
export function setUnauthorizedHandler(fn) { onUnauthorized = fn; }

export async function api(path, { method = 'GET', body, raw = false, text = false } = {}) {
  const opt = { method, headers: { 'X-TWG': '1' }, credentials: 'same-origin', cache: 'no-store' };
  if (body !== undefined) {
    if (raw) {
      opt.body = body;
    } else {
      opt.headers['Content-Type'] = 'application/json';
      opt.body = JSON.stringify(body);
    }
  }
  let res;
  try {
    res = await fetch(path, opt);
  } catch (e) {
    throw new ApiError('Không kết nối được tới máy chủ. Kiểm tra mạng hoặc dịch vụ tuan-wg.', 0);
  }
  if (text && res.ok) return res.text();
  let data = null;
  const ct = res.headers.get('Content-Type') || '';
  if (ct.includes('application/json')) {
    try { data = await res.json(); } catch (e) { data = null; }
  }
  if (!res.ok) {
    const msg = (data && data.error) || ('Lỗi ' + res.status);
    if (res.status === 401 && onUnauthorized && !path.startsWith('/api/login')) onUnauthorized();
    throw new ApiError(msg, res.status);
  }
  return data;
}

export const get = (p) => api(p);
export const post = (p, body) => api(p, { method: 'POST', body: body || {} });
export const put = (p, body) => api(p, { method: 'PUT', body: body || {} });
export const del = (p) => api(p, { method: 'DELETE' });
