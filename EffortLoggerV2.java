/* 
 * Effort Logger Prototype
 * TU13
 * CSE 360 Fa23
 */


package application;

import java.util.ArrayList;
import java.util.List;
import java.util.function.UnaryOperator;

import javafx.application.Application;
import javafx.stage.Stage;
import javafx.util.converter.IntegerStringConverter;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.scene.Scene;
import javafx.scene.control.TextFormatter.Change;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.*;

public class EffortLoggerV2 extends Application {
	
	// store local user data here (should probably add security later)
	private ArrayList<Integer> effortList = new ArrayList<>();
	private ArrayList<String> infoList = new ArrayList<>();
	private ArrayList<CheckBox> checkList = new ArrayList<>();
	private ArrayList<TextField> weightList = new ArrayList<>();
	private ArrayList<String> effortListEncrypted = new ArrayList<>();
	private ArrayList<String> infoListEncrypted = new ArrayList<>();
	
	// login limiter
	private int loginAttempts = 0;
    private static final int MAX_LOGIN_ATTEMPTS = 5;
    
    // set up login interface
    ///
    private TextField usernameField;
    private PasswordField passwordField;
    private ComboBox<String> question1ComboBox;
    private TextField answer1Field;
    private ComboBox<String> question2ComboBox;
    private TextField answer2Field;
    private Label messageLabel;

    private List<UserAccount> userAccounts = new ArrayList<>();    
   
    ///
	
	public static void main(String[] args) {
		launch(args);
	}
    @Override
	public void start(Stage primaryStage) throws Exception {
		
		// Login goes here
    	transitionMain(primaryStage);
    	
		loginScreen(primaryStage);
		
    	
		// load some testing data
		effortList.add(4);
		effortList.add(5);
		infoList.add("Set up new project");
		infoList.add("Completed a module");
		checkList.add(new CheckBox("Effort: " + effortList.get(0) + " Description: " + infoList.get(0) + " Weight: "));
		checkList.add(new CheckBox("Effort: " + effortList.get(1) + " Description: " + infoList.get(1) + " Weight: "));
		
		// have to do some special setup for testing weight input
		
		// uses a filter setup to prevent the user from being able to enter anything but numbers into weight input field
		UnaryOperator<Change> integerFilter = change -> {
			String newText = change.getControlNewText();
			if (newText.matches("([1-9][0-9]*)?")) { 
				return change;
			}
			return null;
		};
		// set up two weight inputs for test data
		for (int i = 0; i < 2; i++)
		{
			TextField weightField = new TextField(); 
			// applies filter to weight input field
			weightField.setTextFormatter(new TextFormatter<Integer>(new IntegerStringConverter(), 0, integerFilter));
			weightField.setText("1"); // set default weight to 1
			weightList.add(weightField);
		}
		
		
//		TwoFactorScreen(primaryStage);
		
	}
	
    //Login and Intrusion Detection
    public void loginScreen(Stage primaryStage) {
        
    	// set title
    	primaryStage.setTitle("EffortLoggerV2 - Login");

        Label statusLabel = new Label();

        // input field for username
        usernameField = new TextField();
        usernameField.setPromptText("Username");

        // input field for password
        passwordField = new PasswordField();
        passwordField.setPromptText("Password");

        // hidden input field for password (shown if show password is selected)
        TextField passwordVisibleField = new TextField();
        passwordVisibleField.setPromptText("Password");
        passwordVisibleField.setManaged(false);
        passwordVisibleField.setVisible(false);
        passwordVisibleField.textProperty().bindBidirectional(passwordField.textProperty());

        // Password visibility toggle
        CheckBox viewPasswordCheckBox = new CheckBox("Show Password");
        viewPasswordCheckBox.setOnAction(e -> {
            boolean showPassword = viewPasswordCheckBox.isSelected();
            passwordField.setManaged(!showPassword);
            passwordField.setVisible(!showPassword);
            passwordVisibleField.setManaged(showPassword);
            passwordVisibleField.setVisible(showPassword);
        });

        // Button to initiate account creation screen
        Button createAccountButton = new Button("Create New Account");
        createAccountButton.setOnAction(event -> createAccountScreen(primaryStage));

        // Login button with action to validate user
        Button loginButton = new Button("Login");
        loginButton.setOnAction(event -> {
            String inputUsername = usernameField.getText();
            String inputPassword = passwordField.isVisible() ? passwordField.getText() : passwordVisibleField.getText();

            UserAccount user = userAccounts.stream()
                                           .filter(account -> account.getUsername().equals(inputUsername))
                                           .findFirst()
                                           .orElse(null);

            if (user != null && user.validatePassword(inputPassword)) {
                // If credentials are valid, proceed to two-factor authentication
                TwoFactorScreen(primaryStage, user);
            } else {
                // Handle failed login
                loginAttempts++;
                if (loginAttempts >= MAX_LOGIN_ATTEMPTS) {
                    loginButton.setDisable(true);
                    statusLabel.setText("Account locked. Please contact the system administrator to reset your password.");
                } else {
                    statusLabel.setText("Login Failed. Attempts left: " + (MAX_LOGIN_ATTEMPTS - loginAttempts));
                }
            }
        });

        // Layout setup
        VBox loginForm = new VBox(10, usernameField, passwordField, passwordVisibleField, viewPasswordCheckBox, loginButton, createAccountButton, statusLabel);
        loginForm.setAlignment(Pos.CENTER);
        loginForm.setPadding(new Insets(15));

        // Set the scene
        primaryStage.setScene(new Scene(loginForm, 800, 600));
        primaryStage.show();
    }

    
    
    public void createAccountScreen(Stage primaryStage) {
        // Set up the VBox layout
    	VBox root = new VBox(10);
        root.setPadding(new Insets(20));

        Label usernameLabel = new Label("Username:");
        usernameField = new TextField();

        Label passwordLabel = new Label("Password:");
        passwordField = new PasswordField();
        
        Label passwordStrengthLabel = new Label("");

        // Listener to update password strength
        passwordField.textProperty().addListener((observable, oldValue, newValue) -> {
            checkPasswordStrength(newValue, passwordStrengthLabel);
        });

        Label question1Label = new Label("Choose a security question:");
        question1ComboBox = new ComboBox<>();
        question1ComboBox.getItems().addAll(
                "What is your mother's maiden name",
                "What is the name of your first pet",
                "What is your favorite book"
        );

        Label answer1Label = new Label("Answer:");
        answer1Field = new TextField();

        Label question2Label = new Label("Choose another security question:");
        question2ComboBox = new ComboBox<>();
        question2ComboBox.getItems().addAll(
                "What is your favorite movie",
                "What city were you born in",
                "What is your favorite color"
        );

        Label answer2Label = new Label("Answer:");
        answer2Field = new TextField();

        Button createAccountButton = new Button("Create Account");
        createAccountButton.setOnAction(e -> {
            String username = usernameField.getText();
            String password = passwordField.getText();
            String question1 = question1ComboBox.getValue();
            String answer1 = answer1Field.getText();
            String question2 = question2ComboBox.getValue();
            String answer2 = answer2Field.getText();
            //account is valid if enter all info including security questions
            boolean isUsernameTaken = userAccounts.stream()
                    .anyMatch(account -> account.getUsername().equalsIgnoreCase(username));

            if (!isUsernameTaken && isAccountValid(username, password, question1, answer1, question2, answer2)) {
            	userAccounts.add(new UserAccount(username, password, question1, answer1, question2, answer2));
            	displayMessage("Account created successfully.");
            } else {
            	// Display appropriate message based on the reason for failure
            	if (isUsernameTaken) {
            		displayMessage("Username is already taken.");
            	} else {
            		displayMessage("Invalid account information.");
            	}
            }
        });
        //upon login it displays message 
        Button loginButton = new Button("Back to Login");
        loginButton.setOnAction(e -> loginScreen(primaryStage));
        
        messageLabel = new Label("");
        //vbox gets all variables
        root.getChildren().addAll(
                usernameLabel,
                usernameField,
                passwordLabel,
                passwordField,
                passwordStrengthLabel,
                question1Label,
                question1ComboBox,
                answer1Label,
                answer1Field,
                question2Label,
                question2ComboBox,
                answer2Label,
                answer2Field,
                createAccountButton,
                loginButton,
                messageLabel
        );

        // Set the scene
        Scene scene = new Scene(root, 800, 600);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void checkPasswordStrength(String password, Label strengthLabel) {
        if (password.isEmpty()) {
            strengthLabel.setText("");
        } else if (isStrongPassword(password)) {
            strengthLabel.setStyle("-fx-text-fill: green;");
            strengthLabel.setText("Strong Password");
        } else if (isOkayPassword(password)) {
            strengthLabel.setStyle("-fx-text-fill: orange;");
            strengthLabel.setText("OK Password");
        } else {
            strengthLabel.setStyle("-fx-text-fill: red;");
            strengthLabel.setText("Weak Password - Include: 7+ characters, a capital letter, a number, and a special character");
        }
    }
    
    private boolean isStrongPassword(String password) {
        return password.matches(".*[A-Z].*") && password.matches(".*\\d.*")
                && password.matches(".*[!@#$%^&*()].*") && password.length() >= 7;
    }

    private boolean isOkayPassword(String password) {
        return password.matches(".*[A-Z].*") && password.matches(".*\\d.*")
                && password.matches(".*[!@#$%^&*()].*");
    }
    
	// adds new effort data to lists and creates a new checkbox and weight input for it that is loaded on scene transition
	public void addData(int effortVal, String desc) {
		this.effortList.add(effortVal);
		this.infoList.add(desc);
		CheckBox newCheck = new CheckBox("Effort: " + effortVal + " Description: " + desc + " Weight: ");
		TextField weightField = new TextField();
		// uses a filter setup to prevent the user from being able to enter anything but numbers into weight input field
		UnaryOperator<Change> integerFilter = change -> {
			String newText = change.getControlNewText();
			if (newText.matches("([1-9][0-9]*)?")) { 
				return change;
			}
			return null;
		};
		// applies filter to weight input field
		weightField.setTextFormatter(new TextFormatter<Integer>(new IntegerStringConverter(), 0, integerFilter));
		checkList.add(newCheck);
		weightList.add(weightField);
		weightField.setText("1"); // set default weight to 1
	}
	
	private float computeAverage() {
		// compute effort average
		int total = 0;
		int dataPoints = 0;
		int weight = 1;
		// only counts selected data
		for(CheckBox Check : checkList) {
			if(Check.isSelected()) {
				weight = Integer.parseInt(weightList.get(checkList.indexOf(Check)).getText());
				total += weight * effortList.get(checkList.indexOf(Check));
				dataPoints += weight;
			}
		}
		
		float avg = total/(float)dataPoints;
		return avg;
	}
	
	// input validation module
	private void transitionValidation(Stage primaryStage) {
		// set up root pane
		VBox validationRoot = new VBox();
				
		// set up labels and input interface
		primaryStage.setTitle("Submit Effort Data");
		Label effortLabel = new Label("write effort value in the box below (positive integer)");
		TextField effortBox = new TextField();
		Label infoLabel = new Label("write an optional short task description below (no #,*,\\,/,\")");
		TextField infoBox = new TextField();
		Button submitButton = new Button("Submit");
		Label resultsLabel = new Label("");
		
		// uses a filter setup to prevent the user from being able to enter anything but numbers into effort data input field
		UnaryOperator<Change> integerFilter = change -> {
	    String newText = change.getControlNewText();
			if (newText.matches("([1-9][0-9]*)?")) { 
				return change;
			}
			return null;
		};
		// applies filter to effort data input field
		effortBox.setTextFormatter(new TextFormatter<Integer>(new IntegerStringConverter(), 0, integerFilter));
				
		// uses a filter setup to prevent the user from being able to enter forbidden characters
		UnaryOperator<Change> textFilter = change -> {
			String newText = change.getControlNewText();
			if (!newText.matches(".*[*#\\\\/\"].*")) { 
				return change;
			}
			return null;
		};
		// applies filter to description field
		infoBox.setTextFormatter(new TextFormatter<String>(textFilter));
				
		// set up submit button functionality
		submitButton.setOnAction(new EventHandler<>() {
			public void handle(ActionEvent event) {
				try {
					int effort = Integer.parseInt(effortBox.getText());
					String description = infoBox.getText();
					resultsLabel.setText("received effort: " + effort + "\nreceived description: " + description);
					addData(effort, description);
					transitionMain(primaryStage);
				}
				catch (NumberFormatException e) {
					resultsLabel.setText("did not receive effort data!");
				}        
			}
		});
				
		// displays interface
		validationRoot.getChildren().add(effortLabel);
		validationRoot.getChildren().add(effortBox);
		validationRoot.getChildren().add(infoLabel);
		validationRoot.getChildren().add(infoBox);
		validationRoot.getChildren().add(submitButton);
		validationRoot.getChildren().add(resultsLabel);
		Scene scene = new Scene(validationRoot,800,600);
		primaryStage.setScene(scene);
		primaryStage.show();
	}
	
	public void transitionMain(Stage primaryStage) {
		// set up root pane
		BorderPane borderPane = new BorderPane();
		VBox root = new VBox();
		
		
		// set up labels and input interface
		primaryStage.setTitle("EffortLoggerv2");
		Label avgLabel = new Label("");
		Button addData = new Button("add new data");
		Button calcAVG = new Button("compute effort average");
		Button planningPokerButton = new Button("Planning Poker");
		Button encrypt = new Button("Encrypt Effort Data");
		calcAVG.setOnAction(new EventHandler<>() {
            public void handle(ActionEvent event) {
            	String labeltext = "average effort: " + computeAverage();
            	if(!labeltext.equals("average effort: NaN")) {
            		avgLabel.setText("average effort: " + computeAverage());
            	} else {
            		avgLabel.setText("No data selelcted!");
            	}
            }
        });
		//planningPoker Button
	    planningPokerButton.setOnAction(event -> PlanningPokerWindow.display(effortList, infoList, weightList));
		
		Button logoutButton = new Button("Logout");

	    logoutButton.setOnAction(event -> {
	        loginScreen(primaryStage);
	    });
	    
	    //encryption button
	    encrypt.setOnAction(event -> {
	        // Transition to the Projects page
	    	transitionToEncryptionScreen(primaryStage);
	    });

		
		// link to input validation prototype
		addData.setOnAction(new EventHandler<>() {
            public void handle(ActionEvent event) {
            	transitionValidation(primaryStage);
            }
        });
		
		//display interface
		root.getChildren().add(avgLabel);
		root.getChildren().add(calcAVG);
		root.getChildren().add(addData);
		root.getChildren().add(planningPokerButton);
		root.getChildren().add(encrypt);
		
		HBox bottomBox = new HBox();
	    bottomBox.setAlignment(Pos.BOTTOM_RIGHT); 
	    HBox.setMargin(logoutButton, new Insets(5, 10, 10, 5));
	    bottomBox.getChildren().add(logoutButton);

	    
	    borderPane.setCenter(root);       
	    borderPane.setBottom(bottomBox); 
		
		// loop for loading each checkbox and its weight input
		for(CheckBox Check : checkList) {
			HBox plate = new HBox();
			plate.getChildren().add(Check);
			plate.getChildren().add(weightList.get(checkList.indexOf(Check)));
			root.getChildren().add(plate);
		}
		
		// set scene
		Scene scene = new Scene(borderPane, 800, 600);
		primaryStage.setScene(scene);
		primaryStage.show();
	}
	
	public void TwoFactorScreen(Stage primaryStage, UserAccount user) {
	    // Set window title
	    primaryStage.setTitle("Two-Factor Authentication");

	    // Create layout
	    VBox root = new VBox(10);
	    root.setPadding(new Insets(20));

	    // Security Question 1
	    Label question1Label = new Label("Security Question 1: " + user.getQuestion1());
	    TextField answer1Field = new TextField();

	    // Security Question 2
	    Label question2Label = new Label("Security Question 2: " + user.getQuestion2());
	    TextField answer2Field = new TextField();

	    // Login button with action to validate security answers
	    Button loginButton = new Button("Login");
	    loginButton.setOnAction(e -> {
	        String answer1 = answer1Field.getText();
	        String answer2 = answer2Field.getText();

	        if (user.validateSecurityAnswers(answer1, answer2)) {
	            // Successful login, proceed to the main application or logged-in screen
	            transitionMain(primaryStage);
	        } else {
	            // Failed login, show error message
	            messageLabel.setText("Invalid security answers.");
	        }
	    });

	    // Back button to return to the login screen
	    Button backButton = new Button("Back");
	    backButton.setOnAction(e -> loginScreen(primaryStage));

	    // Message label for displaying status
	    messageLabel = new Label("");

	    // Add all components to the root layout
	    root.getChildren().addAll(
	            question1Label,
	            answer1Field,
	            question2Label,
	            answer2Field,
	            loginButton,
	            backButton,
	            messageLabel
	    );

	    // Set the scene and show the stage
	    Scene scene = new Scene(root, 800, 600);
	    primaryStage.setScene(scene);
	    primaryStage.show();
	}

    private void displayMessage(String message) {
        messageLabel.setText(message);
    }

    private boolean isCorrectAnswer(String answer, String storedAnswer) {
        
        return answer != null && answer.equals(storedAnswer);
    }

    private boolean isAccountValid(String username, String password, String question1, String answer1, String question2, String answer2) {
        
        return !username.isEmpty() && !password.isEmpty() && !question1.isEmpty() && !answer1.isEmpty() && !question2.isEmpty() && !answer2.isEmpty();
    }

    private boolean isLoginValid(String username, String password, String question1, String answer1, String question2, String answer2) {
        
        for (UserAccount account : userAccounts) {
            if (account.getUsername().equals(username) && account.getPassword().equals(password)) {
                return isCorrectAnswer(answer1, account.getAnswer1()) && isCorrectAnswer(answer2, account.getAnswer2());
            }
        }
        return false;
    }
    
    private void transitionToEncryptionScreen(Stage primaryStage) {
        VBox root = new VBox(10);
        root.setPadding(new Insets(20));

        Label instructionLabel = new Label("Current Data to Encrypt:");
        root.getChildren().add(instructionLabel);

        // Display effort data
        for(int i = 0; i < checkList.size(); i++) {
            Label label = new Label("Effort: " + effortList.get(i) + ", Description: " + infoList.get(i));
            root.getChildren().add(label);
        }
        

        // Encrypt button
        Button encryptButton = new Button("Encrypt");
        encryptButton.setOnAction(e -> {
            // Logic to encrypt  data
            try {
    			encryptData();
    		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
    				| BadPaddingException e1) {
    			// TODO Auto-generated catch block
    			e1.printStackTrace();
    		}
            Label encryptedLabel = new Label("Data encrypted successfully!");
            root.getChildren().add(encryptedLabel);
            
            
            // Display Encrypted Data
    		for(CheckBox checkBox1 : checkList) {
    	    	Label label2 = new Label("Effort: " + effortListEncrypted.get(checkList.indexOf(checkBox1)) + ", Description: " + infoListEncrypted.get(checkList.indexOf(checkBox1)));
    	        root.getChildren().add(label2);
    		}
            
    		// Add a button to return back to main screen
            Button returnButton = new Button("Return to Main Screen");
            returnButton.setOnAction(r -> transitionMain(primaryStage));
            root.getChildren().add(returnButton);
        });
        root.getChildren().add(encryptButton);

        // Set the scene
        Scene scene = new Scene(root, 800, 600);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void encryptData() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
    	// Setup arrayList for storing encrypted data
    	for(CheckBox checkBox : checkList) {
    		effortListEncrypted.add((effortList.get(checkList.indexOf(checkBox))).toString());
    		infoListEncrypted.add(infoList.get(checkList.indexOf(checkBox)));
    	}

    	for(CheckBox checkBox : checkList) {
            String encryptedEffort = encrypt(effortList.get(checkList.indexOf(checkBox)).toString());
            String encryptedInfo = encrypt(infoList.get(checkList.indexOf(checkBox)));
            
            // Store encrypted data
            effortListEncrypted.set(checkList.indexOf(checkBox), encryptedEffort);
            infoListEncrypted.set(checkList.indexOf(checkBox), encryptedInfo);
        }
    }

    private String encrypt(String data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        /*
        Generate secret key, 
        Select Cipher instance - AES algorithm,
        Collect string data 
        */
        SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
        Cipher cipherInstance = Cipher.getInstance("AES");
        String dataToEncrypt = data;

        // Encrypt data
        cipherInstance.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipherInstance.doFinal(dataToEncrypt.getBytes());

        return Base64.getEncoder().encodeToString(encryptedData);
    }
    
    //class for userAccount information
    public class UserAccount {
        private String username;
        private String password;
        private String question1;
        private String answer1;
        private String question2;
        private String answer2;

        public UserAccount(String username, String password, String question1, String answer1, String question2, String answer2) {
            this.username = username;
            this.password = password;
            this.question1 = question1;
            this.answer1 = answer1;
            this.question2 = question2;
            this.answer2 = answer2;
        }
        
        public String getUsername() {
            return username;
        }
        
        public boolean validatePassword(String inputPassword) {
            // In real application, compare password hashes
            return this.password.equals(inputPassword);
        }

        public boolean validateSecurityAnswers(String answer1, String answer2) {
            return this.answer1.equals(answer1) && this.answer2.equals(answer2);
        }


        public String getPassword() {
            return password;
        }
        
        public String getQuestion1() {
        	return question1;
        }
        
        public String getQuestion2() {
        	return question2;
        }

        public String getAnswer1() {
            return answer1;
        }

        public String getAnswer2() {
            return answer2;
        }
    }
    
    public class PlanningPokerWindow{
    	public static void display(ArrayList<Integer> effortList, ArrayList<String> infoList, ArrayList<TextField> weightList) {
            Stage window = new Stage();
            window.setTitle("Planning Poker: Final Card");

            VBox layout = new VBox(10);
            ArrayList<CheckBox> checkBoxList = new ArrayList<>();

            // Display the effort data and checkboxes for final selection
            for (int i = 0; i < effortList.size(); i++) {
                CheckBox checkBox = new CheckBox("Effort: " + effortList.get(i) + " Description: " + infoList.get(i) + "Weight: " + Integer.parseInt(weightList.get(i).getText()));
                checkBoxList.add(checkBox);
                layout.getChildren().add(checkBox);
            }

            // Button to submit the final selection
            Button submitButton = new Button("Submit Final Selection");
            submitButton.setOnAction(e -> handleFinalSelection(checkBoxList, effortList, infoList));

            layout.getChildren().add(submitButton);

            Scene scene = new Scene(layout, 400, 300);
            window.setScene(scene);
            window.showAndWait();
        }
           
        }
    private static void handleFinalSelection(ArrayList<CheckBox> checkBoxList, ArrayList<Integer> effortList, ArrayList<String> infoList) {
        ArrayList<Integer> selectedEfforts = new ArrayList<>();
        ArrayList<String> selectedDescriptions = new ArrayList<>();

        for (CheckBox checkBox : checkBoxList) {
            if (checkBox.isSelected()) {
                int index = checkBoxList.indexOf(checkBox);
                selectedEfforts.add(effortList.get(index));
                selectedDescriptions.add(infoList.get(index));
            }
        }

        if (!selectedEfforts.isEmpty()) {
            // Process the selected efforts and descriptions
            System.out.println("Selected Efforts: " + selectedEfforts);
            System.out.println("Selected Descriptions: " + selectedDescriptions);
        } else {
            System.out.println("No efforts selected.");
        }
    }

}










