use everyout_core_model::*;
use everyout_engine::accounts::*;
fn report(id: &str) -> AccountReport {
    AccountReport::empty(UserId(id.into()), id == "account-b")
}
#[test]
fn failing_account_does_not_abort_other_accounts_and_report_preserves_sections() {
    let plan = AccountsPlan::new(
        PlanId("plan-a".into()),
        vec![
            report("account-a"),
            report("account-b"),
            report("account-c"),
        ],
        ProcessClosePolicy::Ask,
    )
    .unwrap();
    let approval = plan
        .approve(
            ["account-a", "account-b", "account-c"]
                .into_iter()
                .map(|account| AccountConsent {
                    account: account.into(),
                    ..Default::default()
                })
                .collect(),
        )
        .unwrap();
    let mut calls = Vec::new();
    let output = plan.execute(&approval, &|| false, |expected, _| {
        calls.push(expected.account.0.clone());
        if expected.account.0 == "account-a" {
            Err(ErrorKind::AccessDenied)
        } else {
            Ok(expected.clone())
        }
    });
    assert_eq!(calls, ["account-a", "account-b", "account-c"]);
    assert_eq!(output.accounts.len(), 3);
    assert!(!output.accounts[0].issues.is_empty());
    assert!(output.accounts[1].issues.is_empty());
    assert!(output.accounts[1].logged_on);
    assert_eq!(output.scope, AccountScope::AllUsers);
    let json = serde_json::to_string(&output).unwrap();
    for id in calls {
        assert!(json.contains(&id));
    }
    assert!(json.contains(S6_UNVERIFIED));
}
#[test]
fn account_consents_are_unique_scoped_and_cannot_cross_plan_boundaries() {
    let first = AccountsPlan::new(
        PlanId("first".into()),
        vec![report("account-a")],
        ProcessClosePolicy::Ask,
    )
    .unwrap();
    let second = AccountsPlan::new(
        PlanId("second".into()),
        vec![report("account-a")],
        ProcessClosePolicy::Ask,
    )
    .unwrap();
    let consent = AccountConsent {
        account: "account-a".into(),
        windows_dev_confirmed: true,
        ..Default::default()
    };
    assert!(first
        .approve(vec![consent.clone(), consent.clone()])
        .is_err());
    assert!(first
        .approve(vec![AccountConsent {
            account: "unknown".into(),
            ..Default::default()
        }])
        .is_err());
    let approval = first.approve(vec![consent]).unwrap();
    let output = second.execute(&approval, &|| false, |_, _| {
        panic!("foreign approval must not run")
    });
    assert!(!output.accounts[0].issues.is_empty());
}
#[test]
fn cancellation_preserves_one_section_for_every_account() {
    let plan = AccountsPlan::new(
        PlanId("plan".into()),
        vec![report("account-a"), report("account-b")],
        ProcessClosePolicy::Ask,
    )
    .unwrap();
    let output = plan.execute(&plan.approve(vec![]).unwrap(), &|| true, |_, _| {
        panic!("cancelled work")
    });
    assert_eq!(output.accounts.len(), 2);
    assert!(output.accounts.iter().all(|a| !a.issues.is_empty()));
}
