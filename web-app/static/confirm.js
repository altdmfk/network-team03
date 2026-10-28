const actionDialog = document.getElementById('action-confirm');
const applyAction = document.getElementById('confirm-apply');
let pendingAction = null;
document.addEventListener('submit', (event) => {
  const form = event.target.closest('form[data-confirm-title]');
  if (!form) return;
  if (form.dataset.confirmed === 'true') {
    delete form.dataset.confirmed;
    return;
  }
  event.preventDefault();
  pendingAction = { form, submitter: event.submitter };
  document.getElementById('confirm-title').textContent = form.dataset.confirmTitle;
  document.getElementById('confirm-message').textContent = form.dataset.confirmMessage;
  document.getElementById('confirm-note').textContent = form.dataset.confirmNote || '';
  applyAction.textContent = form.dataset.confirmLabel || '확인';
  applyAction.disabled = false;
  actionDialog.showModal();
  document.getElementById('confirm-cancel').focus();
});
document.getElementById('confirm-cancel').addEventListener('click', () => {
  pendingAction = null;
  actionDialog.close();
});
actionDialog.addEventListener('cancel', () => { pendingAction = null; });
applyAction.addEventListener('click', () => {
  if (!pendingAction) return;
  const action = pendingAction;
  pendingAction = null;
  applyAction.disabled = true;
  actionDialog.close();
  action.form.dataset.confirmed = 'true';
  action.form.requestSubmit(action.submitter);
});
