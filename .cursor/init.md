# CFS Initialization

This project uses CFS (Cursor File Structure) to manage instruction documents.

## Structure

- `.cursor/rules/` - Cursor rules documents (.mdc files)
- `.cursor/features/` - Feature request documents
- `.cursor/bugs/` - Bug report documents
- `.cursor/refactors/` - Refactoring task documents
- `.cursor/docs/` - Documentation task documents
- `.cursor/research/` - Research task documents
- `.cursor/progress/` - Progress and handoff documents
- `.cursor/qa/` - QA task documents
- `.cursor/security/` - Security-related documents
- `.cursor/tmp/` - Temporary documents

## Usage

```bash
cfs instructions features create  # Create a feature request
cfs instructions bugs create       # Create a bug report
cfs instructions view              # View all documents
cfs gh sync                        # Sync with GitHub issues
```

## Overview of Project 

This project will serve a simple purpose. It will take in a screenshot of a business card, and it will output either a contact file to add to iOS/Apple contacts or a similar file to add to Google contacts (for example, if you're using Android). If the user is on a mobile device, the application should also have the option of writing directly to iOS or Android contacts if possible. This is all the application will do in the MVP phase. 

The application will use AI to translate the screenshot of the business card into concrete data fields to transfer to a user's contacts list. It should use BAML to make the AI as deterministic as possible to minimize errors. The model for this application is the following: ~/Desktop/receipt-ranger. The receipt range replication takes in receipt screenshots and transforms them into CSV and TSV output data and also writes to Google Sheets. This new contacts application should be simpler in that it won't have a Google Sheets integration. It will simply integrate with the contacts services that I mentioned earlier. But it should follow the pattern established in Receipt Ranger of using BAML to create concrete data fields and rigidly instruct the AI to strictly follow these data fields. The AI should not be doing things like pulling in outside knowledge. For example, information like a business contact's alternate phone number or their email address if it's not listed on the card. All the information that the application outputs to new contact files should represent exactly what's on the card and nothing else. The application is not to infer anything regarding information on the card. It should just slavishly report exactly what's on the card accurately into the contact data field.

### Other application details

- Before actually building the application, the AI agent should work with me in planning it. The agent should come up with a detailed plan which I should sign off on. 
- There should be tests for all the appropriate functionality. 
- The UI should be modern and attractive. The application is Carded. There should be a card motif. 
- The application should be built on a modern framework. The main language for the backend will be Python. We could probably just mimic Receipt Ranger and use Streamlit for the front end, though we need to make sure this is the right call and that it would be better than other possible alternatives. This should be part of the planning phase. 
- This application should be deployed on a modern hosting platform, not Streamlit Community Cloud, as it makes applications look cheesy and unprofessional. Probably something like Render, which I use for my other Streamlit applications.   
- In the building of the application, the AI should use sub-agents. One subagent should be used in the planning phase. At least one should be used in the building phase, and also one for testing and later on for security review. Other sub-agents should be used as appropriate. 
- The current repo is for a web app that can be used on mobile or desktop. Future versions of this project might involve a mobile application in React Native or another technology, but for now, the MVP will be a web application.  
