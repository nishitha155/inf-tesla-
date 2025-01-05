# Inf-TESLA++: A Blockchain-assisted Continuous Authentication Protocol for Broadcast Communication in Resource-Constrained Devices



##  Tech Stack
- **Language**: JavaScript (Node.js)
- **Protocol**: µTESLA, Inf Tesla, Enhanced Inf Tesla, Inf Tesla++
- **Security**: HMAC, Hash Chains

##  Installation Instructions
1. **Unzip the folder**  
   Extract the downloaded project folder to your desired directory.

2. **Run the mutesla protocol**  
   Open your terminal, navigate to the project folder, and run the following command:  
   node mutesla_sender.js
   After server connects and keychain generated the run the command
   node mutesla_receiver.js

3. **Run the inf tesla protocol**  
   Open your terminal, navigate to the project folder, and run the following command:  
   node infsender.js
   After server connects and keychain generated the run the command
   node infreceiver.js

4. **Run the enhanced inf tesla protocol**  
   Open your terminal, navigate to the project folder, and run the following command:  
   node enhsender.js
   After server connects and keychain generated the run the command
   node enhreceiver.js

5. **Run the inf tesla++ protocol**  
   Open your terminal, navigate to the project folder, and run the following command:  
   node inftesla++_owner.js
   After keychain generated the run the command for deterministic mode
   node inftesla++_sender_interval.js for interval based storage algorithm at sender
   node inftesla++_sender_interval.js for logarithmic based storage algorithm at sender
   node inftesla++_sender_interval.js for compression based storage algorithm at sender
   Then run node inftesla++_receiver.js
   After keychain generated the run the command for probabilistic mode
   node probabilistic_inftesla++_sender.js
   Then run node probabilistic_inftesla++_receiver.js

7. **Run the code for packet loss network condition**  
   Open your terminal, navigate to the project folder, and run the following command:  
   node pksender.js
   After server connects and keychain generated the run the command
   node pkreceiver.js
   
