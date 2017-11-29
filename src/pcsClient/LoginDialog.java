package pcsClient;

import java.awt.event.KeyEvent;
import javax.swing.JOptionPane;


public class LoginDialog extends javax.swing.JDialog {
    private Client client;
    private ChatFrame chatFrame;
    private boolean loggedIn = false;
   
    public LoginDialog(java.awt.Frame parent, boolean modal, Client cli) {
        super(parent, modal);
        initComponents();
        client = cli;
        this.chatFrame = (ChatFrame)parent;
    }

    @SuppressWarnings("unchecked")
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        usernameField = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        passwordField = new javax.swing.JPasswordField();
        jLabel3 = new javax.swing.JLabel();
        loginButton = new javax.swing.JButton();
        signupButton = new javax.swing.JButton();
        exitButton = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosed(java.awt.event.WindowEvent evt) {
                formWindowClosed(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("Ubuntu", 1, 36));
        jLabel1.setText("ChatClient");

        jLabel2.setText("Username:");

        passwordField.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                passwordFieldKeyPressed(evt);
            }
        });

        jLabel3.setText("Password:");

        loginButton.setText("Login");
        loginButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loginButtonActionPerformed(evt);
            }
        });

        signupButton.setText("Signup");
        signupButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                signupButtonActionPerformed(evt);
            }
        });

        exitButton.setText("Exit");
        exitButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exitButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap(70, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel2)
                            .addComponent(jLabel3))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(passwordField, javax.swing.GroupLayout.PREFERRED_SIZE, 181, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(usernameField, javax.swing.GroupLayout.PREFERRED_SIZE, 181, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(62, 62, 62))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(loginButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(signupButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(exitButton)
                        .addGap(111, 111, 111))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(jLabel1)
                        .addGap(100, 100, 100))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(29, 29, 29)
                .addComponent(jLabel1)
                .addGap(31, 31, 31)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(usernameField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel2))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(passwordField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel3))
                .addGap(35, 35, 35)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(loginButton)
                    .addComponent(signupButton)
                    .addComponent(exitButton))
                .addContainerGap(61, Short.MAX_VALUE))
        );

        pack();
    }
    
    private void attemptLogin() {
        if (usernameField.getText().length() < 4) { 
            JOptionPane.showMessageDialog(this, "Username must be at least 4 characters long.", "Warning", 0);
        }
        else if ((new String(passwordField.getPassword())).length() < 8) {
            JOptionPane.showMessageDialog(this, "Password must be at least 8 characters long.", "Warning", 0);
        }
        else {
            if(client.login(usernameField.getText(), new String(passwordField.getPassword()))) {
                chatFrame.setVisible(true);
                chatFrame.startChatListener();
                loggedIn = true;
                dispose();
            }
            else {
                JOptionPane.showMessageDialog(this, "Incorrect username or password.", "Warning", 0);
            }
        }
    }
    
    private void loginButtonActionPerformed(java.awt.event.ActionEvent evt) {
        attemptLogin();
    }

    private void signupButtonActionPerformed(java.awt.event.ActionEvent evt) {
        SignupDialog signupDialog = new SignupDialog(chatFrame, true, client);
        signupDialog.setLocationRelativeTo(null);
        signupDialog.setVisible(true);
    }

    private void exitButtonActionPerformed(java.awt.event.ActionEvent evt) {
        client.sendQuitMessage();
        dispose();
        System.exit(0);
    }

    private void passwordFieldKeyPressed(java.awt.event.KeyEvent evt) {
        if (evt.getKeyCode() == KeyEvent.VK_ENTER) {
            attemptLogin();
        }
    }

    private void formWindowClosed(java.awt.event.WindowEvent evt) {
        dispose();
        
        if (!loggedIn) {
            client.sendQuitMessage();
            client.disconnect();
            System.exit(0);
        } 
    }

    
    public char [] getPassword() {
        return passwordField.getPassword();
    }
    
    private javax.swing.JButton exitButton;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JButton loginButton;
    private javax.swing.JPasswordField passwordField;
    private javax.swing.JButton signupButton;
    private javax.swing.JTextField usernameField;
}
