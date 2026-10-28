const keyResult = document.getElementById('issued-key-dialog');
if (keyResult) {
  const input = document.getElementById('new-key');
  keyResult.querySelectorAll('[data-close-key]').forEach(button => button.addEventListener('click', () => keyResult.close()));
  keyResult.addEventListener('close', () => { input.value = ''; });
  window.addEventListener('pagehide', () => { input.value = ''; keyResult.close(); });
  document.getElementById('copy-issued-key').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(input.value);
      document.getElementById('key-copy-status').textContent = '복사했습니다.';
    } catch (_) {
      input.focus(); input.select();
      document.getElementById('key-copy-status').textContent = '선택된 키를 직접 복사해 주세요.';
    }
  });
  keyResult.showModal();
}
const keyDetails = document.getElementById('key-details-dialog');
const reasons = {not_allowed_ip: '비허용 IP 사용 감지', administrator: '관리자 수동 폐기', administrator_bulk: '관리자 일괄 폐기', administrator_replacement: '관리자 키 교체'};
document.querySelectorAll('.key-details-button').forEach(button => button.addEventListener('click', () => {
  for (const field of ['label', 'id', 'source', 'incident', 'reason']) {
    const value = button.dataset['key' + field[0].toUpperCase() + field.slice(1)];
    document.getElementById('key-detail-' + field).textContent = (field === 'reason' ? reasons[value] || value : value) || '—';
  }
  keyDetails.showModal();
}));
document.getElementById('close-key-details').addEventListener('click', () => keyDetails.close());
