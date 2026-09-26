import SwiftUI
import SideSign

struct RenewalCard: View {
    @Bindable var model: RenewalModel
    @State private var showingSignIn = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Keep GPS available", systemImage: "arrow.clockwise.circle")
                .font(.headline)
            if let expiration = model.expiration {
                Text("Expires \(expiration.formatted(date: .abbreviated, time: .shortened))")
                    .font(.subheadline.weight(.semibold))
                if let checked = model.verifiedAt {
                    Text("Installed profile verified by iOS \(checked.formatted(date: .abbreviated, time: .shortened)).")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("Date from this build’s embedded profile. An on-phone refresh has not been verified yet.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            if model.isSignedIn {
                Toggle("Automatic signing refresh", isOn: $model.enabled)
                    .disabled(model.isBusy)
                Text("GPS attempts renewal with three days remaining, when you open it and when iOS allows background work. For a daily trigger, add “Refresh GPS signing” to a Shortcuts automation. Keep LocalDevVPN on and the phone unlocked when it runs.")
                    .font(.caption).foregroundStyle(.secondary)
                Button {
                    Task { _ = try? await model.refresh() }
                } label: {
                    Label(model.isBusy ? "Working…" : "Refresh now", systemImage: "arrow.clockwise")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.isBusy)

                DisclosureGroup("Refresh without Wi-Fi") {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("First prepare the refresh with cellular data on. Then turn cellular off briefly, leave LocalDevVPN on, and install it. Turn cellular back on afterward. These are also separate Shortcuts actions.")
                            .font(.caption).foregroundStyle(.secondary)
                        Text("For an automation, check “GPS signing refresh needed” first. If true: Prepare → Cellular Data off → Wait 2 seconds → Install → Cellular Data on. Install returns true or false so an ordinary refresh error does not stop the next action from restoring data.")
                            .font(.caption).foregroundStyle(.secondary)
                        Button("1. Prepare with internet") {
                            Task { _ = try? await model.prepareOnly() }
                        }
                        .disabled(model.isBusy)
                        Button("2. Install prepared refresh") {
                            Task { _ = try? await model.installPrepared() }
                        }
                        .disabled(model.isBusy || !model.hasPreparedProfile)
                    }
                    .padding(.top, 8)
                }
                .font(.subheadline)
                HStack {
                    Button("Sign in again") { showingSignIn = true }
                    Spacer()
                    Button("Sign out") { Task { await model.signOut() } }
                }
                .font(.caption)
                .disabled(model.isBusy)
            } else {
                Text("Renew the seven-day profile on this iPhone using the Apple Account that signed GPS. Your password is used for sign-in; the saved session stays in this iPhone’s Keychain.")
                    .font(.subheadline).foregroundStyle(.secondary)
                Button("Sign in & enable refresh") { showingSignIn = true }
                    .buttonStyle(.borderedProminent)
            }
            Text(model.status)
                .font(.footnote).foregroundStyle(.secondary)
                .textSelection(.enabled)
            Text("Apple may request sign-in again. Refresh must succeed before GPS expires; iOS cannot launch an expired app to renew itself.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(16)
        .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))
        .sheet(isPresented: $showingSignIn) { RenewalSignInSheet(model: model) }
        .task { await model.reload() }
    }
}

private struct RenewalSignInSheet: View {
    @Bindable var model: RenewalModel
    @Environment(\.dismiss) private var dismiss
    @State private var email = ""
    @State private var password = ""
    @State private var code = ""
    @State private var login: Task<Void, Never>?

    var body: some View {
        NavigationStack {
            Form {
                if let verification = model.verificationRequest {
                    Section("Apple verification") {
                        if case .selectDeliveryMethod(let preferred, let numbers) = verification {
                            Text("Choose where Apple should send your verification code.")
                            if preferred == .trustedDevice {
                                Button("Use a trusted Apple device") {
                                    model.answerVerification(.requestTrustedDevice)
                                }
                            }
                            ForEach(numbers) { number in
                                Button("Text a code to \(number.number)") {
                                    model.answerVerification(.requestSMS(phoneID: number.id))
                                }
                            }
                            if numbers.isEmpty && preferred != .trustedDevice {
                                Text("Apple did not provide an available verification method. Cancel and try signing in again.")
                            }
                        } else {
                            Text("Enter the verification code from your trusted Apple device or phone number.")
                            if verification.error != nil {
                                Text("Apple did not accept that code. Try the latest code.")
                                    .foregroundStyle(.orange)
                            }
                            TextField("Verification code", text: $code)
                                .textContentType(.oneTimeCode)
                                .keyboardType(.numberPad)
                            Button("Verify") {
                                model.answerVerification(.verificationCode(code))
                                code = ""
                            }
                            .disabled(code.count < 6)
                            if case .sms(let numbers, _, _) = verification {
                                ForEach(numbers) { number in
                                    Button("Send another code to \(number.number)") {
                                        model.answerVerification(.requestSMS(phoneID: number.id))
                                    }
                                }
                            }
                        }
                    }
                } else {
                    Section("Apple Account") {
                        TextField("Email address", text: $email)
                            .textContentType(.username)
                            .keyboardType(.emailAddress)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        SecureField("Password", text: $password)
                            .textContentType(.password)
                        Text("Use the account that signed this GPS build. Authentication goes to Apple. The password is not saved.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .disabled(model.isBusy)
                    Section {
                        Button(model.isBusy ? "Signing in…" : "Sign in & enable refresh") {
                            let submittedPassword = password
                            password = ""
                            login = Task {
                                let succeeded = await model.signIn(email: email, password: submittedPassword)
                                if succeeded && !Task.isCancelled { dismiss() }
                            }
                        }
                        .disabled(model.isBusy || email.isEmpty || password.isEmpty)
                    }
                }
                Section { Text(model.status).font(.footnote) }
            }
            .navigationTitle("Signing refresh")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        login?.cancel()
                        model.answerVerification(.cancel)
                        dismiss()
                    }
                }
            }
            .interactiveDismissDisabled(model.isBusy)
            .onDisappear { password = ""; code = "" }
        }
    }
}
