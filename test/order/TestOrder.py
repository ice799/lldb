"""
Test that debug symbols have the correct order as specified by the order file.
"""

import os, time
import re
import unittest
import lldb
import lldbtest

class TestClassTypes(lldbtest.TestBase):

    mydir = "order"

    def test_order(self):
        """Test debug symbols follow the correct order by the order file."""
        res = self.res
        exe = os.path.join(os.getcwd(), "a.out")
        self.ci.HandleCommand("file " + exe, res)
        self.assertTrue(res.Succeeded())

        # Test that the debug symbols have Function f3 before Function f1.
        self.ci.HandleCommand("image dump symtab a.out", res)
        self.assertTrue(res.Succeeded())
        output = res.GetOutput()
        mo_f3 = re.search("Function +.+f3", output)
        mo_f1 = re.search("Function +.+f1", output)
        
        # Match objects for f3 and f1 must exist and f3 must come before f1.
        self.assertTrue(mo_f3 and mo_f1 and mo_f3.start() < mo_f1.start())

        self.ci.HandleCommand("run", res)
        self.assertTrue(res.Succeeded())


if __name__ == '__main__':
    lldb.SBDebugger.Initialize()
    unittest.main()
    lldb.SBDebugger.Terminate()
