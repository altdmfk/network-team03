const composeDialog = document.getElementById('compose-dialog');
document.getElementById('open-compose').addEventListener('click', () => composeDialog.showModal());
composeDialog.querySelectorAll('[data-close-compose]').forEach((button) => {
  button.addEventListener('click', () => composeDialog.close());
});
if (composeDialog.dataset.open === 'true') composeDialog.showModal();
