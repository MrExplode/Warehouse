package me.mrexplode.warehouse;

import java.awt.Color;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.PrintStream;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.border.EmptyBorder;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;


public class MainGUI extends JFrame {

    private static final long serialVersionUID = -6916193571287145835L;
    
    private Warehouse warehouse;
    private File current;
    public static MainGUI instance;

    private JPanel contentPane;
    private JLabel lblJelsz;
    private JPasswordField passwordField;
    private JButton btnOpen;
    private JButton btnClose;
    private JLabel actionLabel;
    private JButton dirSelect;
    protected JProgressBar progressBar;
    private JPasswordField pwd2Field;
    private JLabel lblPasswordAgain;
    private JTextArea console;

    /**
     * Launch the application.
     */
    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {

            @Override
            public void run() {
                try {
                    instance = new MainGUI();
                    instance.setVisible(true);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }
    
    public void displayInfo(String msg) {
        actionLabel.setForeground(Color.BLACK);
        actionLabel.setText(msg);
    }
    
    public void displayError(String msg) {
        actionLabel.setForeground(Color.RED);
        actionLabel.setText(msg);
    }

    /**
     * Create the frame.
     */
    public MainGUI() {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException
                | UnsupportedLookAndFeelException e1) {
            e1.printStackTrace();
        }
        
        setResizable(false);
        setTitle("Warehouse");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setBounds(100, 100, 450, 300);
        contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        setContentPane(contentPane);
        contentPane.setLayout(null);
        
        lblJelsz = new JLabel("Password");
        lblJelsz.setBounds(38, 28, 46, 14);
        contentPane.add(lblJelsz);
        
        lblPasswordAgain = new JLabel("Password again");
        lblPasswordAgain.setBounds(38, 81, 107, 14);
        contentPane.add(lblPasswordAgain);
        
        passwordField = new JPasswordField();
        passwordField.setBounds(38, 53, 107, 20);
        contentPane.add(passwordField);
        
        btnOpen = new JButton("Open");
        btnOpen.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                System.out.println("Open action event fired");
                String pwd = String.valueOf(passwordField.getPassword());
                if (pwd == null || current == null || !pwd.equals(String.valueOf(pwd2Field.getPassword()))) {
                    displayError("Please specify a folder, and give equal passwords!");
                    return;
                }
                
                warehouse = new Warehouse(current, pwd);
                if (!warehouse.checkPassword()) {
                    displayError("Incorrect password for the folder!");
                    return;
                }
                displayInfo("Opening folder...");
                warehouse.unlock();
                displayInfo("Folder opened!");
            }
        });
        
        pwd2Field = new JPasswordField();
        pwd2Field.setBounds(38, 102, 107, 20);
        contentPane.add(pwd2Field);
        btnOpen.setBounds(38, 144, 107, 23);
        contentPane.add(btnOpen);
        
        btnClose = new JButton("Close");
        btnClose.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String pwd = String.valueOf(passwordField.getPassword());
                if (pwd == null || current == null || !pwd.equals(String.valueOf(pwd2Field.getPassword()))) {
                    displayError("Please specify a folder, and give equal passwords!");
                    return;
                }
                warehouse = new Warehouse(current, pwd);
                displayInfo("Closing folder...");
                warehouse.lock();
                displayInfo("Folder closed!");
            }
        });
        btnClose.setBounds(38, 178, 107, 23);
        contentPane.add(btnClose);
        
        actionLabel = new JLabel("");
        actionLabel.setBounds(38, 215, 396, 14);
        contentPane.add(actionLabel);
        
        dirSelect = new JButton("Choose folder");
        dirSelect.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fc = new JFileChooser();
                fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                fc.showOpenDialog(null);
                current = fc.getSelectedFile();
            }
        });
        dirSelect.setBounds(181, 24, 153, 23);
        contentPane.add(dirSelect);
        
        progressBar = new JProgressBar();
        progressBar.setBounds(10, 240, 424, 20);
        contentPane.add(progressBar);
        
        console = new JTextArea();
        console.setBounds(181, 56, 253, 145);
        console.setEditable(false);
        System.setOut(new PrintStream(new StreamCapturer(console, System.out)));
        System.setErr(new PrintStream(new StreamCapturer(console, System.err)));
        JScrollPane scroll = new JScrollPane(console);
        scroll.setBounds(181, 56, 253, 145);
        contentPane.add(scroll);
    }
}
