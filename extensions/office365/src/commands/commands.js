/**
 * AIShields Protect — Office 365 Ribbon Commands
 * Functions executed from ribbon buttons.
 */

/* global Office */

function scanDocument(event) {
  Office.context.ui.displayDialogAsync(
    'https://localhost:3000/taskpane.html',
    { height: 60, width: 30 },
    (result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        result.value.addEventHandler(Office.EventType.DialogMessageReceived, (msg) => {
          console.log('[AIShields] Dialog message:', msg.message);
        });
      }
    }
  );
  event.completed();
}

function checkCompliance(event) {
  Office.context.ui.displayDialogAsync(
    'https://localhost:3000/taskpane.html#compliance',
    { height: 60, width: 30 }
  );
  event.completed();
}

function reportIssue(event) {
  Office.context.ui.displayDialogAsync(
    'https://localhost:3000/taskpane.html#report',
    { height: 40, width: 25 }
  );
  event.completed();
}

// Register functions for ribbon commands
Office.actions = Office.actions || {};
Office.actions.associate('scanDocument', scanDocument);
Office.actions.associate('checkCompliance', checkCompliance);
Office.actions.associate('reportIssue', reportIssue);
