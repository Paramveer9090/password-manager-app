import streamlit as st
import requests

# FastAPI backend URL
API_URL = "http://127.0.0.1:8000"

# Streamlit UI setup
st.set_page_config(page_title="Password Manager", page_icon="🔐", layout="centered")
st.title("🔐 Password Manager & Analyzer")

# Navigation Tabs
tab1, tab2, tab3 = st.tabs(["🔍 Check Password", "💾 Manage Passwords", "⚡ Generate Password"])

# 🛡️ Password Strength Checker
# 🛡️ Password Strength Checker
with tab1:
    st.subheader("🔍 Check Password Strength")
    st.caption("Analyze your password for strength and check if it's been exposed in data breaches.")

    password_to_check = st.text_input(
        "Enter a password to analyze:",
        type="password",
        help="Include uppercase, lowercase, digits, and special characters. At least 12 characters is recommended."
    )

    if st.button("Analyze Password"):
        if password_to_check:
            response = requests.post(f"{API_URL}/check_password/", json={"password": password_to_check})
            if response.status_code == 200:
                result = response.json()
                st.success(f"🔒 Strength: {result['password_strength']['strength']}")
                st.write(f"💡 Suggestions: {', '.join(result['password_strength']['suggestions'])}")

                # Pwned status
                pwned = result["pwned_status"]
                if pwned["status"] == "Compromised":
                    st.error(f"⚠️ This password has been found in {pwned['occurrences']} breaches. Choose another one!")
                elif pwned["status"] == "Safe":
                    st.success("✅ This password has not been found in any known data breaches.")
                else:
                    st.warning(f"⚠️ Could not verify pwned status: {pwned.get('message', 'Unknown error')}")

            else:
                st.error(f"Failed to check password strength: {response.json().get('detail', 'Unknown error')}")
        else:
            st.warning("⚠️ Please enter a password to analyze.")

# 🔐 Save & Retrieve Passwords
# 🔐 Save & Retrieve Passwords
with tab2:
    st.subheader("💾 Save Password")
    st.caption("Securely store your password linked to a unique user ID.")

    user_id = st.text_input("Enter your user ID:", help="Use a unique username or email ID.")
    password_to_save = st.text_input("Enter a password to save:", type="password",
                                     help="Ensure your password is strong before saving.")

    if st.button("Save Password"):
        if user_id and password_to_save:
            response = requests.post(f"{API_URL}/save_password/",
                                     json={"user_id": user_id, "password": password_to_save})
            if response.status_code == 200:
                st.success("✅ Password saved securely!")
            else:
                st.error(f"❌ Failed to save password: {response.json().get('detail', 'Unknown error')}")
        else:
            st.warning("⚠️ Please enter both a user ID and a password.")

    st.divider()

    st.subheader("🔍 Retrieve Password")
    st.caption("Retrieve your saved password using your user ID.")

    user_id_to_retrieve = st.text_input("Enter your user ID to retrieve the password:",
                                        help="This should match the user ID you used when saving the password.")

    if st.button("Retrieve Password"):
        if user_id_to_retrieve:
            response = requests.get(f"{API_URL}/get_password/", params={"user_id": user_id_to_retrieve})
            if response.status_code == 200:
                st.success("🔑 Retrieved Password:")
                st.code(response.json()['password'], language='bash')
            else:
                st.error(f"❌ {response.json().get('detail', 'Failed to retrieve password.')}")
        else:
            st.warning("⚠️ Please enter a user ID.")

# ⚡ Password Generator
# ⚡ Password Generator
with tab3:
    st.subheader("⚡ Generate Strong Password")
    st.caption("Use this tool to create a strong, secure password that meets best practices.")

    length = st.slider("Select password length:", 12, 32, 16, help="Longer passwords are more secure.")
    exclude_special = st.checkbox("Exclude special characters (e.g., @, #, $)", help="Useful if some apps restrict special characters.")

    if st.button("Generate Password"):
        params = {"length": length}
        if exclude_special:
            params["exclude_special"] = True

        response = requests.get(f"{API_URL}/generate_password/", params=params)
        if response.status_code == 200:
            generated_password = response.json()["password"]
            st.success("🔐 Your Generated Password:")
            st.code(generated_password, language='bash')
        else:
            st.error("❌ Failed to generate password. Please try again.")

