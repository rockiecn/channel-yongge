// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package channel

import (
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
)

// ChannelABI is the input ABI used to generate the binding from.
const ChannelABI = "[{\"inputs\":[{\"internalType\":\"addresspayable\",\"name\":\"to\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"timeout\",\"type\":\"uint256\"}],\"stateMutability\":\"payable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"}],\"name\":\"AlterOwner\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"closeChannel\",\"type\":\"event\"},{\"inputs\":[],\"name\":\"ChannelTimeout\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"hash\",\"type\":\"bytes32\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"sign\",\"type\":\"bytes\"}],\"name\":\"CloseChannel\",\"outputs\":[],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"alterOwner\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"addTime\",\"type\":\"uint256\"}],\"name\":\"extend\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getInfo\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getOwner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"stateMutability\":\"payable\",\"type\":\"receive\"}]"

// ChannelBin is the compiled bytecode used for deploying new contracts.
var ChannelBin = "0x6080604052738026796fd7ce63eae824314aa5bacf55643e893d600560006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550735ef5fd065210cbd62dfe86cc68a0e1ab2c5cba50600660006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550604051610f30380380610f30833981810160405260408110156100d057600080fd5b810190808051906020019092919080519060200190929190505050336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1663de60908a6040518163ffffffff1660e01b815260040160206040518083038186803b15801561019557600080fd5b505afa1580156101a9573d6000803e3d6000fd5b505050506040513d60208110156101bf57600080fd5b81019080805190602001909291905050509050600161ffff168161ffff1610610250576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260188152602001807f6465706c6f79206368616e6e656c2069732062616e6e6564000000000000000081525060200191505060405180910390fd5b6000821161025d57600080fd5b82600260006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055504260038190555081600481905550505050610c31806102ff6000396000f3fe6080604052600436106100595760003560e01c80630ca05f9f146100655780632b7fa6be146100cc578063396582451461019b5780635a9b0b89146101b2578063893d20e81461021e5780639714378c1461025f57610060565b3661006057005b600080fd5b34801561007157600080fd5b506100b46004803603602081101561008857600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061029a565b60405180821515815260200191505060405180910390f35b610199600480360360608110156100e257600080fd5b8101908080359060200190929190803590602001909291908035906020019064010000000081111561011357600080fd5b82018360208201111561012557600080fd5b8035906020019184600183028401116401000000008311171561014757600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290505050610439565b005b3480156101a757600080fd5b506101b0610891565b005b3480156101be57600080fd5b506101c761095c565b604051808581526020018481526020018373ffffffffffffffffffffffffffffffffffffffff1681526020018273ffffffffffffffffffffffffffffffffffffffff16815260200194505050505060405180910390f35b34801561022a57600080fd5b506102336109bc565b604051808273ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561026b57600080fd5b506102986004803603602081101561028257600080fd5b81019080803590602001909291905050506109e5565b005b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161461035e576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260138152602001807f6f6e6c79206f776e65722063616e2063616c6c0000000000000000000000000081525060200191505060405180910390fd5b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050826000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055507f8c153ecee6895f15da72e646b4029e0ef7cbf971986d8d9cfe48c5563d368e908184604051808373ffffffffffffffffffffffffffffffffffffffff1681526020018273ffffffffffffffffffffffffffffffffffffffff1681526020019250505060405180910390a16001915050919050565b600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146104fc576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600e8152602001807f696c6c6567616c2063616c6c657200000000000000000000000000000000000081525060200191505060405180910390fd5b60003083604051602001808373ffffffffffffffffffffffffffffffffffffffff1660601b8152601401828152602001925050506040516020818303038152906040528051906020012090508381146105bd576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600c8152602001807f696c6c6567616c2068617368000000000000000000000000000000000000000081525060200191505060405180910390fd5b6000600660009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166319045a2586856040518363ffffffff1660e01b81526004018083815260200180602001828103825283818151815260200191508051906020019080838360005b83811015610654578082015181840152602081019050610639565b50505050905090810190601f1680156106815780820380516001836020036101000a031916815260200191505b50935050505060206040518083038186803b15801561069f57600080fd5b505afa1580156106b3573d6000803e3d6000fd5b505050506040513d60208110156106c957600080fd5b81019080805190602001909291905050509050600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff161461079f576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600b8152602001807f696c6c6567616c2073696700000000000000000000000000000000000000000081525060200191505060405180910390fd5b600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166108fc859081150290604051600060405180830381858888f19350505050158015610807573d6000803e3d6000fd5b503373ffffffffffffffffffffffffffffffffffffffff167f01d42a9c1bb0e1a3464994bd2306368ef80e0dcf460c6123b5f7cbbcbf169fbb856040518082815260200191505060405180910390a2600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16ff5b60035460045460035401116108a557600080fd5b42600454600354011115610921576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600e8152602001807f54696d65206973206e6f7420757000000000000000000000000000000000000081525060200191505060405180910390fd5b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16ff5b600080600080600354600454600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16935093509350935090919293565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610aa6576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260138152602001807f6f6e6c79206f776e65722063616e2063616c6c0000000000000000000000000081525060200191505060405180910390fd5b6000600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1663de60908a6040518163ffffffff1660e01b815260040160206040518083038186803b158015610b1057600080fd5b505afa158015610b24573d6000803e3d6000fd5b505050506040513d6020811015610b3a57600080fd5b81019080805190602001909291905050509050600161ffff168161ffff1610610bcb576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260108152602001807f657874656e642069732062616e6e65640000000000000000000000000000000081525060200191505060405180910390fd5b60008211610bd857600080fd5b6000826004540190506004548111610bef57600080fd5b8060048190555050505056fea2646970667358221220b5079c4662b25baba3913017f3d378e52aeba078e611c7b26b459d8bd36f03b564736f6c63430007030033"

// DeployChannel deploys a new Ethereum contract, binding an instance of Channel to it.
func DeployChannel(auth *bind.TransactOpts, backend bind.ContractBackend, to common.Address, timeout *big.Int) (common.Address, *types.Transaction, *Channel, error) {
	parsed, err := abi.JSON(strings.NewReader(ChannelABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}

	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(ChannelBin), backend, to, timeout)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Channel{ChannelCaller: ChannelCaller{contract: contract}, ChannelTransactor: ChannelTransactor{contract: contract}, ChannelFilterer: ChannelFilterer{contract: contract}}, nil
}

// Channel is an auto generated Go binding around an Ethereum contract.
type Channel struct {
	ChannelCaller     // Read-only binding to the contract
	ChannelTransactor // Write-only binding to the contract
	ChannelFilterer   // Log filterer for contract events
}

// ChannelCaller is an auto generated read-only Go binding around an Ethereum contract.
type ChannelCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ChannelTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ChannelTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ChannelFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ChannelFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ChannelSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ChannelSession struct {
	Contract     *Channel          // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ChannelCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ChannelCallerSession struct {
	Contract *ChannelCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts  // Call options to use throughout this session
}

// ChannelTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ChannelTransactorSession struct {
	Contract     *ChannelTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// ChannelRaw is an auto generated low-level Go binding around an Ethereum contract.
type ChannelRaw struct {
	Contract *Channel // Generic contract binding to access the raw methods on
}

// ChannelCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ChannelCallerRaw struct {
	Contract *ChannelCaller // Generic read-only contract binding to access the raw methods on
}

// ChannelTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ChannelTransactorRaw struct {
	Contract *ChannelTransactor // Generic write-only contract binding to access the raw methods on
}

// NewChannel creates a new instance of Channel, bound to a specific deployed contract.
func NewChannel(address common.Address, backend bind.ContractBackend) (*Channel, error) {
	contract, err := bindChannel(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Channel{ChannelCaller: ChannelCaller{contract: contract}, ChannelTransactor: ChannelTransactor{contract: contract}, ChannelFilterer: ChannelFilterer{contract: contract}}, nil
}

// NewChannelCaller creates a new read-only instance of Channel, bound to a specific deployed contract.
func NewChannelCaller(address common.Address, caller bind.ContractCaller) (*ChannelCaller, error) {
	contract, err := bindChannel(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ChannelCaller{contract: contract}, nil
}

// NewChannelTransactor creates a new write-only instance of Channel, bound to a specific deployed contract.
func NewChannelTransactor(address common.Address, transactor bind.ContractTransactor) (*ChannelTransactor, error) {
	contract, err := bindChannel(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ChannelTransactor{contract: contract}, nil
}

// NewChannelFilterer creates a new log filterer instance of Channel, bound to a specific deployed contract.
func NewChannelFilterer(address common.Address, filterer bind.ContractFilterer) (*ChannelFilterer, error) {
	contract, err := bindChannel(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ChannelFilterer{contract: contract}, nil
}

// bindChannel binds a generic wrapper to an already deployed contract.
func bindChannel(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(ChannelABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Channel *ChannelRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _Channel.Contract.ChannelCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Channel *ChannelRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Channel.Contract.ChannelTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Channel *ChannelRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Channel.Contract.ChannelTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Channel *ChannelCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _Channel.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Channel *ChannelTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Channel.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Channel *ChannelTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Channel.Contract.contract.Transact(opts, method, params...)
}

// GetInfo is a free data retrieval call binding the contract method 0x5a9b0b89.
//
// Solidity: function getInfo() view returns(uint256, uint256, address, address)
func (_Channel *ChannelCaller) GetInfo(opts *bind.CallOpts) (*big.Int, *big.Int, common.Address, common.Address, error) {
	var (
		ret0 = new(*big.Int)
		ret1 = new(*big.Int)
		ret2 = new(common.Address)
		ret3 = new(common.Address)
	)
	out := &[]interface{}{
		ret0,
		ret1,
		ret2,
		ret3,
	}
	err := _Channel.contract.Call(opts, out, "getInfo")
	return *ret0, *ret1, *ret2, *ret3, err
}

// GetInfo is a free data retrieval call binding the contract method 0x5a9b0b89.
//
// Solidity: function getInfo() view returns(uint256, uint256, address, address)
func (_Channel *ChannelSession) GetInfo() (*big.Int, *big.Int, common.Address, common.Address, error) {
	return _Channel.Contract.GetInfo(&_Channel.CallOpts)
}

// GetInfo is a free data retrieval call binding the contract method 0x5a9b0b89.
//
// Solidity: function getInfo() view returns(uint256, uint256, address, address)
func (_Channel *ChannelCallerSession) GetInfo() (*big.Int, *big.Int, common.Address, common.Address, error) {
	return _Channel.Contract.GetInfo(&_Channel.CallOpts)
}

// GetOwner is a free data retrieval call binding the contract method 0x893d20e8.
//
// Solidity: function getOwner() view returns(address)
func (_Channel *ChannelCaller) GetOwner(opts *bind.CallOpts) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := ret0
	err := _Channel.contract.Call(opts, out, "getOwner")
	return *ret0, err
}

// GetOwner is a free data retrieval call binding the contract method 0x893d20e8.
//
// Solidity: function getOwner() view returns(address)
func (_Channel *ChannelSession) GetOwner() (common.Address, error) {
	return _Channel.Contract.GetOwner(&_Channel.CallOpts)
}

// GetOwner is a free data retrieval call binding the contract method 0x893d20e8.
//
// Solidity: function getOwner() view returns(address)
func (_Channel *ChannelCallerSession) GetOwner() (common.Address, error) {
	return _Channel.Contract.GetOwner(&_Channel.CallOpts)
}

// ChannelTimeout is a paid mutator transaction binding the contract method 0x39658245.
//
// Solidity: function ChannelTimeout() returns()
func (_Channel *ChannelTransactor) ChannelTimeout(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Channel.contract.Transact(opts, "ChannelTimeout")
}

// ChannelTimeout is a paid mutator transaction binding the contract method 0x39658245.
//
// Solidity: function ChannelTimeout() returns()
func (_Channel *ChannelSession) ChannelTimeout() (*types.Transaction, error) {
	return _Channel.Contract.ChannelTimeout(&_Channel.TransactOpts)
}

// ChannelTimeout is a paid mutator transaction binding the contract method 0x39658245.
//
// Solidity: function ChannelTimeout() returns()
func (_Channel *ChannelTransactorSession) ChannelTimeout() (*types.Transaction, error) {
	return _Channel.Contract.ChannelTimeout(&_Channel.TransactOpts)
}

// CloseChannel is a paid mutator transaction binding the contract method 0x2b7fa6be.
//
// Solidity: function CloseChannel(bytes32 hash, uint256 value, bytes sign) payable returns()
func (_Channel *ChannelTransactor) CloseChannel(opts *bind.TransactOpts, hash [32]byte, value *big.Int, sign []byte) (*types.Transaction, error) {
	return _Channel.contract.Transact(opts, "CloseChannel", hash, value, sign)
}

// CloseChannel is a paid mutator transaction binding the contract method 0x2b7fa6be.
//
// Solidity: function CloseChannel(bytes32 hash, uint256 value, bytes sign) payable returns()
func (_Channel *ChannelSession) CloseChannel(hash [32]byte, value *big.Int, sign []byte) (*types.Transaction, error) {
	return _Channel.Contract.CloseChannel(&_Channel.TransactOpts, hash, value, sign)
}

// CloseChannel is a paid mutator transaction binding the contract method 0x2b7fa6be.
//
// Solidity: function CloseChannel(bytes32 hash, uint256 value, bytes sign) payable returns()
func (_Channel *ChannelTransactorSession) CloseChannel(hash [32]byte, value *big.Int, sign []byte) (*types.Transaction, error) {
	return _Channel.Contract.CloseChannel(&_Channel.TransactOpts, hash, value, sign)
}

// AlterOwner is a paid mutator transaction binding the contract method 0x0ca05f9f.
//
// Solidity: function alterOwner(address newOwner) returns(bool)
func (_Channel *ChannelTransactor) AlterOwner(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _Channel.contract.Transact(opts, "alterOwner", newOwner)
}

// AlterOwner is a paid mutator transaction binding the contract method 0x0ca05f9f.
//
// Solidity: function alterOwner(address newOwner) returns(bool)
func (_Channel *ChannelSession) AlterOwner(newOwner common.Address) (*types.Transaction, error) {
	return _Channel.Contract.AlterOwner(&_Channel.TransactOpts, newOwner)
}

// AlterOwner is a paid mutator transaction binding the contract method 0x0ca05f9f.
//
// Solidity: function alterOwner(address newOwner) returns(bool)
func (_Channel *ChannelTransactorSession) AlterOwner(newOwner common.Address) (*types.Transaction, error) {
	return _Channel.Contract.AlterOwner(&_Channel.TransactOpts, newOwner)
}

// Extend is a paid mutator transaction binding the contract method 0x9714378c.
//
// Solidity: function extend(uint256 addTime) returns()
func (_Channel *ChannelTransactor) Extend(opts *bind.TransactOpts, addTime *big.Int) (*types.Transaction, error) {
	return _Channel.contract.Transact(opts, "extend", addTime)
}

// Extend is a paid mutator transaction binding the contract method 0x9714378c.
//
// Solidity: function extend(uint256 addTime) returns()
func (_Channel *ChannelSession) Extend(addTime *big.Int) (*types.Transaction, error) {
	return _Channel.Contract.Extend(&_Channel.TransactOpts, addTime)
}

// Extend is a paid mutator transaction binding the contract method 0x9714378c.
//
// Solidity: function extend(uint256 addTime) returns()
func (_Channel *ChannelTransactorSession) Extend(addTime *big.Int) (*types.Transaction, error) {
	return _Channel.Contract.Extend(&_Channel.TransactOpts, addTime)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_Channel *ChannelTransactor) Receive(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Channel.contract.RawTransact(opts, nil) // calldata is disallowed for receive function
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_Channel *ChannelSession) Receive() (*types.Transaction, error) {
	return _Channel.Contract.Receive(&_Channel.TransactOpts)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_Channel *ChannelTransactorSession) Receive() (*types.Transaction, error) {
	return _Channel.Contract.Receive(&_Channel.TransactOpts)
}

// ChannelAlterOwnerIterator is returned from FilterAlterOwner and is used to iterate over the raw logs and unpacked data for AlterOwner events raised by the Channel contract.
type ChannelAlterOwnerIterator struct {
	Event *ChannelAlterOwner // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ChannelAlterOwnerIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ChannelAlterOwner)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ChannelAlterOwner)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ChannelAlterOwnerIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ChannelAlterOwnerIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ChannelAlterOwner represents a AlterOwner event raised by the Channel contract.
type ChannelAlterOwner struct {
	From common.Address
	To   common.Address
	Raw  types.Log // Blockchain specific contextual infos
}

// FilterAlterOwner is a free log retrieval operation binding the contract event 0x8c153ecee6895f15da72e646b4029e0ef7cbf971986d8d9cfe48c5563d368e90.
//
// Solidity: event AlterOwner(address from, address to)
func (_Channel *ChannelFilterer) FilterAlterOwner(opts *bind.FilterOpts) (*ChannelAlterOwnerIterator, error) {

	logs, sub, err := _Channel.contract.FilterLogs(opts, "AlterOwner")
	if err != nil {
		return nil, err
	}
	return &ChannelAlterOwnerIterator{contract: _Channel.contract, event: "AlterOwner", logs: logs, sub: sub}, nil
}

// WatchAlterOwner is a free log subscription operation binding the contract event 0x8c153ecee6895f15da72e646b4029e0ef7cbf971986d8d9cfe48c5563d368e90.
//
// Solidity: event AlterOwner(address from, address to)
func (_Channel *ChannelFilterer) WatchAlterOwner(opts *bind.WatchOpts, sink chan<- *ChannelAlterOwner) (event.Subscription, error) {

	logs, sub, err := _Channel.contract.WatchLogs(opts, "AlterOwner")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ChannelAlterOwner)
				if err := _Channel.contract.UnpackLog(event, "AlterOwner", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAlterOwner is a log parse operation binding the contract event 0x8c153ecee6895f15da72e646b4029e0ef7cbf971986d8d9cfe48c5563d368e90.
//
// Solidity: event AlterOwner(address from, address to)
func (_Channel *ChannelFilterer) ParseAlterOwner(log types.Log) (*ChannelAlterOwner, error) {
	event := new(ChannelAlterOwner)
	if err := _Channel.contract.UnpackLog(event, "AlterOwner", log); err != nil {
		return nil, err
	}
	return event, nil
}

// ChannelCloseChannelIterator is returned from FilterCloseChannel and is used to iterate over the raw logs and unpacked data for CloseChannel events raised by the Channel contract.
type ChannelCloseChannelIterator struct {
	Event *ChannelCloseChannel // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ChannelCloseChannelIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ChannelCloseChannel)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ChannelCloseChannel)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ChannelCloseChannelIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ChannelCloseChannelIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ChannelCloseChannel represents a CloseChannel event raised by the Channel contract.
type ChannelCloseChannel struct {
	From  common.Address
	Value *big.Int
	Raw   types.Log // Blockchain specific contextual infos
}

// FilterCloseChannel is a free log retrieval operation binding the contract event 0x01d42a9c1bb0e1a3464994bd2306368ef80e0dcf460c6123b5f7cbbcbf169fbb.
//
// Solidity: event closeChannel(address indexed from, uint256 value)
func (_Channel *ChannelFilterer) FilterCloseChannel(opts *bind.FilterOpts, from []common.Address) (*ChannelCloseChannelIterator, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}

	logs, sub, err := _Channel.contract.FilterLogs(opts, "closeChannel", fromRule)
	if err != nil {
		return nil, err
	}
	return &ChannelCloseChannelIterator{contract: _Channel.contract, event: "closeChannel", logs: logs, sub: sub}, nil
}

// WatchCloseChannel is a free log subscription operation binding the contract event 0x01d42a9c1bb0e1a3464994bd2306368ef80e0dcf460c6123b5f7cbbcbf169fbb.
//
// Solidity: event closeChannel(address indexed from, uint256 value)
func (_Channel *ChannelFilterer) WatchCloseChannel(opts *bind.WatchOpts, sink chan<- *ChannelCloseChannel, from []common.Address) (event.Subscription, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}

	logs, sub, err := _Channel.contract.WatchLogs(opts, "closeChannel", fromRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ChannelCloseChannel)
				if err := _Channel.contract.UnpackLog(event, "closeChannel", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseCloseChannel is a log parse operation binding the contract event 0x01d42a9c1bb0e1a3464994bd2306368ef80e0dcf460c6123b5f7cbbcbf169fbb.
//
// Solidity: event closeChannel(address indexed from, uint256 value)
func (_Channel *ChannelFilterer) ParseCloseChannel(log types.Log) (*ChannelCloseChannel, error) {
	event := new(ChannelCloseChannel)
	if err := _Channel.contract.UnpackLog(event, "closeChannel", log); err != nil {
		return nil, err
	}
	return event, nil
}
