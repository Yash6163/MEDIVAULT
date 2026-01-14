// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title MediVault Medical Records Contract
 * @dev Stores encrypted hashes of medical records on blockchain for tamper-proof verification
 */
contract MediVault {
    
    // Struct to store record information
    struct MedicalRecordHash {
        string recordHash;
        address patientAddress;
        uint256 timestamp;
        bool exists;
    }
    
    // Mapping from record hash to record details
    mapping(string => MedicalRecordHash) private records;
    
    // Mapping from patient address to their record hashes
    mapping(address => string[]) private patientRecords;
    
    // Events
    event RecordStored(
        address indexed patient,
        string recordHash,
        uint256 timestamp
    );
    
    event RecordVerified(
        string recordHash,
        address indexed verifier,
        bool exists
    );
    
    /**
     * @dev Store a new medical record hash
     * @param recordHash The SHA-256 hash of the encrypted medical record
     */
    function storeRecordHash(string memory recordHash) public returns (bool) {
        require(bytes(recordHash).length > 0, "Hash cannot be empty");
        require(!records[recordHash].exists, "Record already exists");
        
        records[recordHash] = MedicalRecordHash({
            recordHash: recordHash,
            patientAddress: msg.sender,
            timestamp: block.timestamp,
            exists: true
        });
        
        patientRecords[msg.sender].push(recordHash);
        
        emit RecordStored(msg.sender, recordHash, block.timestamp);
        
        return true;
    }
    
    /**
     * @dev Verify if a record hash exists and get its details
     * @param recordHash The hash to verify
     * @return exists Whether the record exists
     * @return timestamp When the record was stored
     */
    function verifyRecordHash(string memory recordHash) 
        public 
        view 
        returns (bool exists, uint256 timestamp) 
    {
        MedicalRecordHash memory record = records[recordHash];
        return (record.exists, record.timestamp);
    }
    
    /**
     * @dev Get all record hashes for a patient
     * @param patient The patient's address
     * @return Array of record hashes
     */
    function getPatientRecords(address patient) 
        public 
        view 
        returns (string[] memory) 
    {
        require(
            msg.sender == patient || msg.sender == owner,
            "Unauthorized access"
        );
        return patientRecords[patient];
    }
    
    /**
     * @dev Get record details by hash
     * @param recordHash The hash to look up
     * @return patientAddress The address that stored the record
     * @return timestamp When it was stored
     * @return exists Whether the record exists
     */
    function getRecordDetails(string memory recordHash)
        public
        view
        returns (
            address patientAddress,
            uint256 timestamp,
            bool exists
        )
    {
        MedicalRecordHash memory record = records[recordHash];
        return (
            record.patientAddress,
            record.timestamp,
            record.exists
        );
    }
    
    /**
     * @dev Get total number of records for a patient
     * @param patient The patient's address
     * @return count Number of records
     */
    function getRecordCount(address patient) public view returns (uint256) {
        return patientRecords[patient].length;
    }
    
    // Owner functionality for contract management
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this");
        _;
    }
    
    /**
     * @dev Transfer ownership
     * @param newOwner The new owner address
     */
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Invalid address");
        owner = newOwner;
    }
}

/**
 * @title MediVaultAccessControl
 * @dev Extended contract with access control features
 */
contract MediVaultAccessControl is MediVault {
    
    // Struct for access permissions
    struct AccessPermission {
        address grantedTo;
        uint256 expiryTime;
        bool isActive;
    }
    
    // Mapping: patient => (hospital/doctor => permission)
    mapping(address => mapping(address => AccessPermission)) private accessPermissions;
    
    // Events
    event AccessGranted(
        address indexed patient,
        address indexed provider,
        uint256 expiryTime
    );
    
    event AccessRevoked(
        address indexed patient,
        address indexed provider
    );
    
    /**
     * @dev Grant access to a healthcare provider
     * @param provider Address of the healthcare provider
     * @param durationInDays How long the access should last
     */
    function grantAccess(address provider, uint256 durationInDays) public {
        require(provider != address(0), "Invalid provider address");
        require(durationInDays > 0, "Duration must be positive");
        
        uint256 expiryTime = block.timestamp + (durationInDays * 1 days);
        
        accessPermissions[msg.sender][provider] = AccessPermission({
            grantedTo: provider,
            expiryTime: expiryTime,
            isActive: true
        });
        
        emit AccessGranted(msg.sender, provider, expiryTime);
    }
    
    /**
     * @dev Revoke access from a healthcare provider
     * @param provider Address of the provider to revoke
     */
    function revokeAccess(address provider) public {
        require(
            accessPermissions[msg.sender][provider].isActive,
            "No active permission exists"
        );
        
        accessPermissions[msg.sender][provider].isActive = false;
        
        emit AccessRevoked(msg.sender, provider);
    }
    
    /**
     * @dev Check if a provider has active access to patient records
     * @param patient The patient's address
     * @param provider The provider's address
     * @return hasAccess Whether access is granted and active
     */
    function checkAccess(address patient, address provider) 
        public 
        view 
        returns (bool hasAccess) 
    {
        AccessPermission memory permission = accessPermissions[patient][provider];
        
        if (!permission.isActive) {
            return false;
        }
        
        if (block.timestamp > permission.expiryTime) {
            return false;
        }
        
        return true;
    }
    
    /**
     * @dev Get access permission details
     * @param patient Patient address
     * @param provider Provider address
     * @return isActive Whether permission is active
     * @return expiryTime When permission expires
     */
    function getAccessDetails(address patient, address provider)
        public
        view
        returns (bool isActive, uint256 expiryTime)
    {
        AccessPermission memory permission = accessPermissions[patient][provider];
        return (permission.isActive, permission.expiryTime);
    }
}