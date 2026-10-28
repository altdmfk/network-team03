// Retain each list's open/closed state independently during page navigation.
document.querySelectorAll('details[data-persist-accordion]').forEach((list) => {
  const key = `enginesquare:${location.pathname}:${list.id}`;
  try {
    const saved = sessionStorage.getItem(key);
    if (saved !== null) list.open = saved === 'open';
  } catch (_) { /* The lists still work when browser storage is disabled. */ }
  list.addEventListener('toggle', () => {
    try { sessionStorage.setItem(key, list.open ? 'open' : 'closed'); } catch (_) {}
  });
});

// Page controls in the summary must not also toggle the accordion.
document.querySelectorAll('summary .pagination').forEach((pager) => {
  pager.addEventListener('click', (event) => {
    event.stopPropagation();
    if (!event.target.closest('a')) {
      event.preventDefault();
    } else if (!event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey) {
      try {
        sessionStorage.setItem(`enginesquare:scroll:${location.pathname}`,
          JSON.stringify({ x: window.scrollX, y: window.scrollY }));
      } catch (_) {}
    }
  });
});

// Restore the viewport after the next page has restored its accordion layout.
window.addEventListener('pageshow', () => {
  const key = `enginesquare:scroll:${location.pathname}`;
  try {
    const saved = sessionStorage.getItem(key);
    if (saved === null) return;
    sessionStorage.removeItem(key);
    const position = JSON.parse(saved);
    if (!Number.isFinite(position.x) || !Number.isFinite(position.y)) return;
    requestAnimationFrame(() => {
      window.scrollTo({ left: position.x, top: position.y, behavior: 'instant' });
    });
  } catch (_) {}
});
