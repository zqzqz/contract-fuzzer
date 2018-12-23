var Debugger = require('remix-debug').EthDebugger;
var BreakpointManager = require('remix-debug').BreakpointManager;

var myDebugger = new Debugger({
  compilationResult: () => {
    return compilationResult // that helps resolving source location
  }
})

myDebugger.addProvider(web3, 'web3')
myDebugger.switchProvider('web3')

var breakPointManager = new remixCore.code.BreakpointManager(this.myDebugger, (sourceLocation) => {
    // return offsetToLineColumn
})
myDebugger.setBreakpointManager(breakPointManager)
breakPointManager.add({fileName, row})
breakPointManager.add({fileName, row})

myDebugger.debug(<tx_hash>)

myDebugger.event.register('newTraceLoaded', () => {
  // start doing basic stuff like retrieving step details
  myDebugger.traceManager.getCallStackAt(34, (error, callstack) => {})
})

myDebugger.callTree.register('callTreeReady', () => {
  // start doing more complex stuff like resolvng local variables
  breakPointManager.jumpNextBreakpoint(true)
  
  var storageView = myDebugger.storageViewAt(38, <contract address>, 
  storageView.storageSlot(0, (error, storage) => {})
  storageView.storageRange(error, storage) => {}) // retrieve 0 => 1000 slots

  myDebugger.extractStateAt(23, (error, state) => {
    myDebugger.decodeStateAt(23, state, (error, decodedState) => {})
  })
  
  myDebugger.sourceLocationFromVMTraceIndex(<contract address>, 23, (error, location) => {
    myDebugger.decodeLocalsAt(23, location, (error, decodedlocals) => {})
  })
  
  myDebugger.extractLocalsAt(23, (null, locals) => {})
  
})