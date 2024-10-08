use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program::{invoke},
    program_error::ProgramError,
    pubkey::Pubkey,
};
use std::convert::TryInto;

use borsh::{BorshDeserialize, BorshSerialize};
use spl_token::{
    instruction::{mint_to, transfer, burn},
    state::Mint,
};
use solana_program::program_pack::Pack;

#[derive(Default, BorshSerialize, BorshDeserialize, Debug)]
pub struct TokenConfig {
    pub max_supply: u64,
    pub initialized: bool,
    pub admin_pubkey: Pubkey,
}

pub enum CustomError {
    MaxSupplyExceeded = 0x1,
    UnauthorizedMint = 0x2,
    InvalidAmount = 0x3,
}

impl From<CustomError> for ProgramError {
    fn from(e: CustomError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

// This function here will deserialize the u64 amount from instruction data, for security reasons
fn decode_amount(data: &[u8]) -> Result<u64, ProgramError> {
    if data.len() != 8 {
        return Err(CustomError::InvalidAmount.into());
    }
    Ok(u64::from_le_bytes(data.try_into().map_err(|_| ProgramError::InvalidInstructionData)?))
}

// This function here will check the signer for security reason
fn check_signer(account: &AccountInfo) -> ProgramResult {
    if !account.is_signer {
        msg!("Missing required signature for account: {}", account.key);
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let (instruction, rest_of_data) = instruction_data.split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match instruction {
        0 => process_transfer(accounts, rest_of_data),
        1 => process_mint(accounts, rest_of_data, program_id),
        2 => process_burn(accounts, rest_of_data),
        3 => process_initialize(accounts, rest_of_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_initialize(accounts: &[AccountInfo], rest_of_data: &[u8]) -> ProgramResult {
    if rest_of_data.len() < 40 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let admin_pubkey = Pubkey::new_from_array(rest_of_data[..32].try_into().unwrap());
    let max_supply = u64::from_le_bytes(rest_of_data[32..40].try_into().unwrap());

    let account_info_iter = &mut accounts.iter();
    let config_account = next_account_info(account_info_iter)?;

    // Ensure account size is enough for TokenConfig
    if config_account.data_len() < TokenConfig::default().try_to_vec()?.len() {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut config_data = config_account.try_borrow_mut_data()?;
    let mut token_config = TokenConfig::try_from_slice(&config_data).map_err(|_| ProgramError::InvalidAccountData)?;

    if token_config.initialized {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    token_config.admin_pubkey = admin_pubkey;
    token_config.max_supply = max_supply;
    token_config.initialized = true;

    token_config.serialize(&mut *config_data)?;

    msg!("Token initialized with admin: {} and max supply: {}", admin_pubkey, max_supply);
    Ok(())
}

fn process_transfer(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    let amount = decode_amount(instruction_data)?;

    if amount == 0 {
        return Err(CustomError::InvalidAmount.into());
    }

    let account_info_iter = &mut accounts.iter();
    let from_account = next_account_info(account_info_iter)?;
    let to_account = next_account_info(account_info_iter)?;
    let authority = next_account_info(account_info_iter)?;
    let token_program = next_account_info(account_info_iter)?;

    msg!("Transferring {} tokens from {} to {}", amount, from_account.key, to_account.key);
    
    let transfer_ix = transfer(
        token_program.key,
        from_account.key,
        to_account.key,
        authority.key,
        &[],
        amount,
    )?;

    invoke(&transfer_ix, &[from_account.clone(), to_account.clone(), authority.clone()])?;
    Ok(())
}

fn process_mint(accounts: &[AccountInfo], instruction_data: &[u8], _program_id: &Pubkey) -> ProgramResult {
    let amount = decode_amount(instruction_data)?;

    let account_info_iter = &mut accounts.iter();
    let mint_account = next_account_info(account_info_iter)?;
    let destination_account = next_account_info(account_info_iter)?;
    let mint_authority = next_account_info(account_info_iter)?;
    let token_program = next_account_info(account_info_iter)?;
    let config_account = next_account_info(account_info_iter)?;

    // Now we check the authority for the signer that is minting
    check_signer(mint_authority)?;

    let config_data = config_account.try_borrow_data()?;
    let token_config: TokenConfig = TokenConfig::try_from_slice(&config_data).map_err(|_| ProgramError::InvalidAccountData)?;

    if *mint_authority.key != token_config.admin_pubkey {
        msg!("Unauthorized: Only the admin can mint tokens.");
        return Err(CustomError::UnauthorizedMint.into());
    }

    let mint_state = Mint::unpack(&mint_account.try_borrow_data()?)?;
    let current_supply = mint_state.supply;

    if current_supply + amount > token_config.max_supply {
        msg!("Minting would exceed max supply limit of {}", token_config.max_supply);
        return Err(CustomError::MaxSupplyExceeded.into());
    }

    msg!("Minting {} tokens to {}", amount, destination_account.key);
    let mint_ix = mint_to(
        token_program.key,
        mint_account.key,
        destination_account.key,
        mint_authority.key,
        &[],
        amount,
    )?;

    invoke(&mint_ix, &[mint_account.clone(), destination_account.clone(), mint_authority.clone()])?;
    Ok(())
}

fn process_burn(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    let amount = decode_amount(instruction_data)?;

    let account_info_iter = &mut accounts.iter();
    let burn_account = next_account_info(account_info_iter)?;
    let mint_account = next_account_info(account_info_iter)?;
    let burn_authority = next_account_info(account_info_iter)?;
    let token_program = next_account_info(account_info_iter)?;

    // Let's check the signer if has furn authority, this is a good measure against attack and will help Brett to protect
    check_signer(burn_authority)?;

    msg!("Burning {} tokens from {}", amount, burn_account.key);
    let burn_ix = burn(
        token_program.key,
        burn_account.key,
        mint_account.key,
        burn_authority.key,
        &[],
        amount,
    )?;

    invoke(&burn_ix, &[burn_account.clone(), mint_account.clone(), burn_authority.clone()])?;
    Ok(())
}

entrypoint!(process_instruction);
